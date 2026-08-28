use chrono::Local;
use clap::{Arg, Command};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Instant;
mod cracker;
use crate::cracker::{crack_passwords_multithread, is_supported_algorithm};
use num_cpus;
mod hash_detect;
use crate::hash_detect::detect_hash_algo;
mod expander;
mod search_space;
mod telemetry;
use crate::expander::{
    GeneratedCandidate, expand_candidates, expand_candidates_with_provenance,
    expand_ranked_candidates_with_provenance,
};
use crate::search_space::{AllowedPatterns, SearchSpace, default_allowed_patterns_path};
use crate::telemetry::{CrackRunRecord, CrackedPasswordPattern, seconds, throughput};

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationContext {
    persona_json: serde_json::Value,
    llm_model_id: String,
    llm_raw_output: String,
    search_space: SearchSpace,
}

/// ------------------------------------------------------------
/// MAIN
/// ------------------------------------------------------------
fn main() {
    let matches = Command::new("Password Generator")
        .version("1.5.0")
        .author("Daniel Egbeleke")
        .about("Expands an LLM search space and optionally verifies candidates against a hash.")
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("INPUT_FILE")
                .help("Path to input persona file (defaults to first file in persona_examples folder)")
                .num_args(1),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("OUTPUT_FILE")
                .help("Path or directory for output file (defaults to output/ folder)")
                .num_args(1),
        )
        .arg(
            Arg::new("length")
                .short('l')
                .long("length")
                .value_name("LENGTH")
                .help("Length of each generated password (default: 12)")
                .num_args(1),
        )
        .arg(
            Arg::new("amount")
                .short('a')
                .long("amount")
                .value_name("AMOUNT")
                .help("Number of passwords to generate (default: 20)")
                .num_args(1),
        )
        .arg(
            Arg::new("allowed-patterns")
                .long("allowed-patterns")
                .value_name("PATH")
                .help(
                    "Validated non-symbol fallback pattern file (default: config/allowed_patterns.txt)",
                )
                .num_args(1),
        )
        .arg(
            Arg::new("crack")
                .long("crack")
                .value_name("TARGET_HASH")
                .help("Hash to crack by comparing against provided generated passwords (i.e. --crack <<HASH>>)")
                .num_args(1),
        )
        .arg(
            Arg::new("algo")
                .long("algo")
                .value_name("HASH_ALGO")
                .help("Hash algorithm: sha256, sha512, md5, bcrypt, argon2")
                .num_args(1),
        )
        .arg(
            Arg::new("threads")
                .long("threads")
                .value_name("N")
                .help("Max number of CPU threads to use for cracking (default = all cores)")
                .num_args(1),
        )
        .arg(
            Arg::new("condition")
                .long("condition")
                .value_name("NAME")
                .help("Experimental condition label (default: ranked_search)"),
        )
        .arg(
            Arg::new("persona-id")
                .long("persona-id")
                .value_name("ID")
                .help("Stable persona identifier for the research record"),
        )
        .arg(
            Arg::new("observed-length")
                .long("observed-length")
                .value_name("N")
                .help("Known observed password length, if available"),
        )
        .arg(
            Arg::new("observed-pattern")
                .long("observed-pattern")
                .value_name("PATTERN")
                .help("Known observed password pattern, if available"),
        )
        .arg(
            Arg::new("data-output")
                .long("data-output")
                .value_name("PATH")
                .help("Path for the per-run JSON record"),
        )
        .get_matches();

    // Resolve input file
    let input_path = matches
        .get_one::<String>("input")
        .map(PathBuf::from)
        .unwrap_or_else(|| get_default_persona_file());

    if matches.get_one::<String>("crack").is_some() && matches.get_one::<String>("input").is_none()
    {
        eprintln!("Crack mode requires --input PATH_TO_PERSONA_JSON.");
        std::process::exit(2);
    }

    if !input_path.is_file() {
        eprintln!("Error: persona JSON file not found: {:?}", input_path);
        std::process::exit(1);
    }

    let allowed_patterns_path = matches
        .get_one::<String>("allowed-patterns")
        .map(PathBuf::from)
        .unwrap_or_else(default_allowed_patterns_path);
    let allowed_patterns = match AllowedPatterns::from_file(&allowed_patterns_path) {
        Ok(patterns) => patterns,
        Err(error) => {
            eprintln!("Allowed-patterns configuration failed: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "Loaded {} allowed fallback patterns from {:?}",
        allowed_patterns.len(),
        allowed_patterns_path
    );

    // Resolve output path
    let output_path = matches
        .get_one::<String>("output")
        .map(PathBuf::from)
        .unwrap_or_else(|| generate_default_output_path(&input_path));

    let requested_length = matches
        .get_one::<String>("length")
        .and_then(|v| v.parse::<usize>().ok());

    let length = requested_length.unwrap_or(12);

    if length == 0 || length > 32 {
        eprintln!("Length must be between 1 and 32.");
        std::process::exit(2);
    }

    let amount = matches
        .get_one::<String>("amount")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2000);

    if amount == 0 {
        eprintln!("Amount must be greater than zero.");
        std::process::exit(2);
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("Failed to create output directory");
    }

    let infinite_mode = matches.get_one::<String>("crack").is_some()
        && matches.get_one::<String>("amount").is_none();

    let generation_started = Instant::now();
    let GenerationContext {
        persona_json,
        llm_model_id,
        llm_raw_output,
        search_space,
    } = match run_python_ai(&input_path) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("Search-space generation failed: {error}");
            std::process::exit(1);
        }
    };

    if let Some(hash_to_crack) = matches.get_one::<String>("crack") {
        let max_threads = matches
            .get_one::<String>("threads")
            .and_then(|v| v.parse::<usize>().ok());

        // Algorithm: CLI override, otherwise auto-detect.
        let algo = matches
            .get_one::<String>("algo")
            .map(|s| s.as_str())
            .unwrap_or_else(|| {
                let detected = detect_hash_algo(hash_to_crack);
                if detected == "unsupported" {
                    eprintln!("Unable to detect a supported hash algorithm; use --algo.");
                    std::process::exit(2);
                }
                println!("Auto-detected hash type: {}", detected);
                detected
            });

        if !is_supported_algorithm(algo) {
            eprintln!("Unsupported hash algorithm: {algo}");
            std::process::exit(2);
        }

        println!("\n=== Crack Mode Enabled ===");
        println!("→ Target Hash: {}", hash_to_crack);
        println!("→ Algorithm: {}", algo);
        println!("→ Threads: {}\n", max_threads.unwrap_or_else(num_cpus::get));

        // --------------------------------------------------------
        // NORMAL MODE (user specified amount or length)
        // --------------------------------------------------------
        if !infinite_mode {
            let candidates = if let Some(length) = requested_length {
                expand_candidates_with_provenance(&search_space, &allowed_patterns, length, amount)
            } else {
                let lengths = ranked_lengths(&search_space);
                let mut excluded = HashSet::new();
                expand_ranked_candidates_with_provenance(
                    &search_space,
                    &allowed_patterns,
                    &lengths,
                    amount,
                    &mut excluded,
                )
            };
            let generation_time = generation_started.elapsed();
            let result =
                crack_passwords_multithread(&candidates, hash_to_crack.clone(), algo, max_threads);
            let total_runtime = generation_started.elapsed();
            let cracked_password_pattern = cracked_password_pattern(result.rank, &candidates);

            if result.cracked {
                println!("MATCH FOUND!");
                if let Some(password) = result.matched_password.as_deref() {
                    println!("Password: {password}");
                }
                if let Some(hash) = result.matched_hash.as_deref() {
                    println!("Hash: {hash}");
                }
            } else {
                println!("No match found.");
            }

            println!("Time taken: {:?}", result.time_taken);
            let threads = max_threads.unwrap_or_else(num_cpus::get).max(1);
            let record = CrackRunRecord {
                run_id: create_id("run"),
                condition: matches
                    .get_one::<String>("condition")
                    .cloned()
                    .unwrap_or_else(|| {
                        if requested_length.is_some() {
                            "exact_length".to_string()
                        } else {
                            "ranked_search".to_string()
                        }
                    }),
                persona_id: matches
                    .get_one::<String>("persona-id")
                    .cloned()
                    .unwrap_or_else(|| create_id("persona")),
                hash_algorithm: algo.to_string(),
                target_hash: hash_to_crack.to_string(),
                persona_json: persona_json.clone(),
                llm_model_id: llm_model_id.clone(),
                llm_raw_output: llm_raw_output.clone(),
                validated_search_space: search_space.clone(),
                search_space_size: result.candidates_checked,
                cracked: result.cracked,
                rank: result.rank,
                cracked_password_pattern,
                time_to_first_match_seconds: result.cracked.then(|| seconds(total_runtime)),
                total_runtime_seconds: seconds(total_runtime),
                generation_time_seconds: seconds(generation_time),
                verification_time_seconds: seconds(result.time_taken),
                threads_utilization: threads as f64 / num_cpus::get().max(1) as f64,
                candidate_throughput: throughput(result.candidates_checked, result.time_taken),
                generation_throughput: throughput(result.candidates_checked, generation_time),
                observed_password_length: matches
                    .get_one::<String>("observed-length")
                    .and_then(|value| value.parse().ok()),
                observed_pattern: matches.get_one::<String>("observed-pattern").cloned(),
            };
            let data_path = matches
                .get_one::<String>("data-output")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    Path::new("output/crack_runs").join(format!("{}.json", record.run_id))
                });
            if let Err(error) = record.write_json(&data_path) {
                eprintln!("Could not write run record {:?}: {}", data_path, error);
            } else {
                println!("Run record written to {:?}", data_path);
            }
            return;
        }

        // --------------------------------------------------------
        // INFINITE MODE
        // --------------------------------------------------------
        println!("∞ Infinite cracking mode activated.");
        if let Some(length) = requested_length {
            println!("→ Every candidate will be exactly {} characters.", length);
        } else {
            println!("→ Model-ranked lengths are followed by the full 4–32 range.");
        }
        println!("→ System will generate increasing batches until cracked.\n");

        let mut batch_size = 100; // starting batch size
        let lengths = requested_length
            .map(|length| vec![length])
            .unwrap_or_else(|| ranked_lengths(&search_space));
        let mut excluded = HashSet::new();
        let mut total_candidates = 0;
        let mut total_verification_time = std::time::Duration::ZERO;

        loop {
            let candidates = expand_ranked_candidates_with_provenance(
                &search_space,
                &allowed_patterns,
                &lengths,
                batch_size,
                &mut excluded,
            );

            if candidates.is_empty() {
                println!("Search space exhausted without a match.");
                write_infinite_run_record(
                    &matches,
                    hash_to_crack,
                    algo,
                    &persona_json,
                    &llm_model_id,
                    &llm_raw_output,
                    &search_space,
                    total_candidates,
                    false,
                    None,
                    None,
                    generation_started,
                    total_verification_time,
                );
                return;
            }
            total_candidates += candidates.len();
            let batch_len = candidates.len();

            // 3. Crack batch
            let result =
                crack_passwords_multithread(&candidates, hash_to_crack.clone(), algo, max_threads);
            total_verification_time += result.time_taken;

            if result.cracked {
                println!("\nMATCH FOUND!");
                if let Some(password) = result.matched_password.as_deref() {
                    println!("Password: {password}");
                }
                if let Some(hash) = result.matched_hash.as_deref() {
                    println!("Hash: {hash}");
                }
                println!("Time Taken: {:?}", result.time_taken);
                let cracked_password_pattern = cracked_password_pattern(result.rank, &candidates);
                write_infinite_run_record(
                    &matches,
                    hash_to_crack,
                    algo,
                    &persona_json,
                    &llm_model_id,
                    &llm_raw_output,
                    &search_space,
                    total_candidates,
                    true,
                    result.rank.map(|rank| total_candidates - batch_len + rank),
                    cracked_password_pattern,
                    generation_started,
                    total_verification_time,
                );
                return;
            }

            batch_size = batch_size.saturating_mul(2);
        }
    }

    let generated_candidates = expand_candidates(&search_space, &allowed_patterns, length, amount);
    let mut file = File::create(&output_path).expect("Failed to create output file");
    for password in &generated_candidates {
        writeln!(file, "{password}").expect("Failed to write to file");
    }
    println!(
        "Generated {} candidates (len: {}) → {:?}",
        generated_candidates.len(),
        length,
        output_path
    );
}

fn cracked_password_pattern(
    rank: Option<usize>,
    candidates: &[GeneratedCandidate],
) -> Option<CrackedPasswordPattern> {
    let candidate = candidates.get(rank?.checked_sub(1)?);

    candidate.map(|candidate| CrackedPasswordPattern {
        source_pattern: candidate.source_pattern.clone(),
        source_phase: candidate.source_phase.clone(),
        case_variant: candidate.case_variant.clone(),
    })
}

fn write_infinite_run_record(
    matches: &clap::ArgMatches,
    hash_to_crack: &str,
    algo: &str,
    persona_json: &serde_json::Value,
    llm_model_id: &str,
    llm_raw_output: &str,
    validated_search_space: &SearchSpace,
    search_space_size: usize,
    cracked: bool,
    batch_rank: Option<usize>,
    cracked_password_pattern: Option<CrackedPasswordPattern>,
    run_started: Instant,
    verification_time: std::time::Duration,
) {
    let threads = matches
        .get_one::<String>("threads")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(num_cpus::get)
        .max(1);
    let total_runtime = run_started.elapsed();
    let generation_time = total_runtime.saturating_sub(verification_time);
    let record = CrackRunRecord {
        run_id: create_id("run"),
        condition: matches
            .get_one::<String>("condition")
            .cloned()
            .unwrap_or_else(|| "ranked_search_infinite".to_string()),
        persona_id: matches
            .get_one::<String>("persona-id")
            .cloned()
            .unwrap_or_else(|| create_id("persona")),
        hash_algorithm: algo.to_string(),
        target_hash: hash_to_crack.to_string(),
        persona_json: persona_json.clone(),
        llm_model_id: llm_model_id.to_string(),
        llm_raw_output: llm_raw_output.to_string(),
        validated_search_space: validated_search_space.clone(),
        search_space_size,
        cracked,
        rank: batch_rank,
        cracked_password_pattern,
        time_to_first_match_seconds: cracked.then(|| seconds(total_runtime)),
        total_runtime_seconds: seconds(total_runtime),
        generation_time_seconds: seconds(generation_time),
        verification_time_seconds: seconds(verification_time),
        threads_utilization: threads as f64 / num_cpus::get().max(1) as f64,
        candidate_throughput: throughput(search_space_size, verification_time),
        generation_throughput: throughput(search_space_size, generation_time),
        observed_password_length: matches
            .get_one::<String>("observed-length")
            .and_then(|value| value.parse().ok()),
        observed_pattern: matches.get_one::<String>("observed-pattern").cloned(),
    };
    let data_path = matches
        .get_one::<String>("data-output")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new("output/crack_runs").join(format!("{}.json", record.run_id)));
    if let Err(error) = record.write_json(&data_path) {
        eprintln!("Could not write run record {:?}: {}", data_path, error);
    } else {
        println!("Run record written to {:?}", data_path);
    }
}

/// ------------------------------------------------------------
/// PYTHON AI GENERATION
/// ------------------------------------------------------------
fn run_python_ai(input_file: &Path) -> std::io::Result<GenerationContext> {
    #[cfg(target_os = "windows")]
    let venv_python = Path::new("venv").join("Scripts").join("python.exe");

    #[cfg(not(target_os = "windows"))]
    let venv_python = Path::new("venv").join("bin").join("python3");

    let python_path = if venv_python.exists() {
        venv_python.to_str().unwrap().to_string()
    } else {
        println!("No virtual environment found. Creating one...");
        let status = ProcessCommand::new("python")
            .arg("-m")
            .arg("venv")
            .arg("venv")
            .status()
            .expect("Failed to create virtual environment");

        if !status.success() {
            eprintln!("Error: Could not create virtual environment.");
            std::process::exit(1);
        }

        venv_python.to_str().unwrap().to_string()
    };

    let mut cmd = ProcessCommand::new(&python_path);

    cmd.arg("ai_logic/main.py").arg("--input").arg(input_file);

    let output = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;

    if !output.status.success() {
        if !output.stderr.is_empty() {
            eprint!(
                "LLM/Python diagnostics:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Python script failed",
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_generation_context(stdout.trim())
}

fn parse_generation_context(stdout: &str) -> std::io::Result<GenerationContext> {
    let GenerationContext {
        persona_json,
        llm_model_id,
        llm_raw_output,
        search_space,
    } = serde_json::from_str(stdout.trim()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid model-generation JSON from Python: {error}"),
        )
    })?;
    if !persona_json.is_object() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "model-generation JSON contains a non-object persona_json",
        ));
    }
    if llm_model_id.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "model-generation JSON contains an empty llm_model_id",
        ));
    }
    let search_space = search_space
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;

    Ok(GenerationContext {
        persona_json,
        llm_model_id,
        llm_raw_output,
        search_space,
    })
}

/// ------------------------------------------------------------
/// HELPERS
/// ------------------------------------------------------------
fn get_default_persona_file() -> PathBuf {
    let folder = Path::new("persona_examples");
    if let Ok(entries) = fs::read_dir(folder) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                return path;
            }
        }
    }
    eprintln!("No default persona file found in {:?}", folder);
    std::process::exit(1);
}

fn generate_default_output_path(input_path: &Path) -> PathBuf {
    let output_dir = Path::new("output");
    let stem = input_path
        .file_stem()
        .unwrap_or_else(|| std::ffi::OsStr::new("output"));
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let filename = format!("{}_{}.txt", stem.to_string_lossy(), timestamp);
    output_dir.join(filename)
}

fn create_id(prefix: &str) -> String {
    let timestamp = Local::now().format("%Y%m%d%H%M%S%f");
    let id = format!("{}-{}-{}", prefix, timestamp, std::process::id());
    id
}

fn ranked_lengths(search_space: &SearchSpace) -> Vec<usize> {
    let mut lengths = Vec::new();
    for length in search_space
        .likely_lengths
        .iter()
        .copied()
        .filter(|length| (4..=32).contains(length))
    {
        if !lengths.contains(&length) {
            lengths.push(length);
        }
    }
    for length in 4..=32 {
        if !lengths.contains(&length) {
            lengths.push(length);
        }
    }
    lengths
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{cracked_password_pattern, parse_generation_context, ranked_lengths};
    use crate::expander::GeneratedCandidate;
    use crate::search_space::SearchSpace;

    #[test]
    fn ranked_search_covers_every_supported_length_after_model_lengths() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["1999".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token}{year}".to_string()],
            likely_lengths: vec![6, 12, 6],
            pattern_weights: HashMap::new(),
        };

        let lengths = ranked_lengths(&search_space);

        assert_eq!(&lengths[..2], &[6, 12]);
        assert!(lengths.iter().all(|length| (4..=32).contains(length)));
        assert_eq!(lengths.len(), 29);
    }

    #[test]
    fn parses_and_validates_the_model_generation_envelope() {
        let context = parse_generation_context(
            r#"{
                "persona_json": {"persona": {"name": "Dan"}},
                "llm_model_id": "test-model",
                "llm_raw_output": "raw model output",
                "search_space": {
                    "primary_tokens": ["Dan"],
                    "secondary_tokens": [],
                    "important_numbers": ["99"],
                    "preferred_symbols": ["!"],
                    "likely_patterns": ["{token}{number}"],
                    "likely_lengths": [5],
                    "pattern_weights": {"{token}{number}": 0.9}
                }
            }"#,
        )
        .unwrap();

        assert_eq!(context.persona_json["persona"]["name"], "Dan");
        assert_eq!(context.llm_model_id, "test-model");
        assert_eq!(context.llm_raw_output, "raw model output");
        assert_eq!(context.search_space.primary_tokens, vec!["Dan"]);
    }

    #[test]
    fn records_provenance_for_the_matched_candidate_rank() {
        let candidates = vec![GeneratedCandidate {
            password: "Dan99".to_string(),
            source_pattern: "{token}{number}".to_string(),
            source_phase: "weighted_model".to_string(),
            case_variant: "original".to_string(),
        }];

        let pattern = cracked_password_pattern(Some(1), &candidates).unwrap();

        assert_eq!(pattern.source_pattern, "{token}{number}");
        assert_eq!(pattern.source_phase, "weighted_model");
        assert_eq!(pattern.case_variant, "original");
        assert!(cracked_password_pattern(Some(2), &candidates).is_none());
    }
}

// fn load_passwords_from_output(output_file: &Path) -> Vec<String> {
//     let file = File::open(output_file).expect("Failed to open generated password file");
//     let reader = BufReader::new(file);
//     reader.lines().filter_map(Result::ok).collect()
// }
