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
use crate::search_space::{
    AllowedPatterns, DEFAULT_MAX_TOKEN_SLOTS, MAX_TOKEN_SLOTS, SearchSpace,
    default_allowed_patterns_path, validate_max_token_slots,
};
use crate::telemetry::{CrackRunRecord, CrackedPasswordPattern, seconds, throughput};

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationContext {
    persona_json: serde_json::Value,
    llm_model_id: String,
    llm_raw_output: String,
    search_space: SearchSpace,
}

struct AggregateVerificationMetrics {
    candidates_generated: usize,
    actual_candidates_evaluated: usize,
    configured_threads: usize,
    peak_active_worker_threads: usize,
}

impl AggregateVerificationMetrics {
    fn new(configured_threads: usize) -> Self {
        Self {
            candidates_generated: 0,
            actual_candidates_evaluated: 0,
            configured_threads,
            peak_active_worker_threads: 0,
        }
    }

    fn record_batch(
        &mut self,
        candidates_generated: usize,
        actual_candidates_evaluated: usize,
        active_worker_threads: usize,
    ) {
        self.candidates_generated = self
            .candidates_generated
            .saturating_add(candidates_generated);
        self.actual_candidates_evaluated = self
            .actual_candidates_evaluated
            .saturating_add(actual_candidates_evaluated);
        self.peak_active_worker_threads =
            self.peak_active_worker_threads.max(active_worker_threads);
    }
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
                .help("Number of passwords to generate (default: 2000 outside crack mode)")
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
            Arg::new("max-token-slots")
                .long("max-token-slots")
                .value_name("N")
                .help("Maximum indexed token slots per pattern (default: 6; maximum: 32)")
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

    let input_path = matches
        .get_one::<String>("input")
        .map(PathBuf::from)
        .unwrap_or_else(get_default_persona_file);

    if matches.get_one::<String>("crack").is_some() && matches.get_one::<String>("input").is_none()
    {
        eprintln!("Crack mode requires --input PATH_TO_PERSONA_JSON.");
        std::process::exit(2);
    }

    if !input_path.is_file() {
        eprintln!("Error: persona JSON file not found: {:?}", input_path);
        std::process::exit(1);
    }

    let max_token_slots = match matches.get_one::<String>("max-token-slots") {
        Some(value) => match value.parse::<usize>() {
            Ok(value) => value,
            Err(_) => {
                eprintln!("--max-token-slots must be an integer between 1 and {MAX_TOKEN_SLOTS}.");
                std::process::exit(2);
            }
        },
        None => DEFAULT_MAX_TOKEN_SLOTS,
    };
    if let Err(error) = validate_max_token_slots(max_token_slots) {
        eprintln!("Invalid --max-token-slots value: {error}.");
        std::process::exit(2);
    }

    let allowed_patterns_path = matches
        .get_one::<String>("allowed-patterns")
        .map(PathBuf::from)
        .unwrap_or_else(default_allowed_patterns_path);
    let allowed_patterns = match AllowedPatterns::from_file_with_max_token_slots(
        &allowed_patterns_path,
        max_token_slots,
    ) {
        Ok(patterns) => patterns,
        Err(error) => {
            eprintln!("Allowed-patterns configuration failed: {error}");
            std::process::exit(2);
        }
    };
    println!(
        "Loaded {} allowed fallback entries from {:?} (up to {} token slots)",
        allowed_patterns.len(),
        allowed_patterns_path,
        max_token_slots,
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
    let configured_threads = if matches.get_one::<String>("crack").is_some() {
        Some(match matches.get_one::<String>("threads") {
            Some(value) => match value.parse::<usize>() {
                Ok(value) if value > 0 => value,
                _ => {
                    eprintln!("--threads must be a positive integer.");
                    std::process::exit(2);
                }
            },
            None => num_cpus::get().max(1),
        })
    } else {
        None
    };

    let generation_started = Instant::now();
    let GenerationContext {
        persona_json,
        llm_model_id,
        llm_raw_output,
        search_space,
    } = match run_python_ai(&input_path, max_token_slots) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("Search-space generation failed: {error}");
            std::process::exit(1);
        }
    };

    if let Some(hash_to_crack) = matches.get_one::<String>("crack") {
        let configured_threads =
            configured_threads.expect("crack mode resolves a positive configured thread count");

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
        println!("→ Configured verifier threads: {}\n", configured_threads);

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
            let result = crack_passwords_multithread(
                &candidates,
                hash_to_crack.clone(),
                algo,
                Some(configured_threads),
            );
            let total_runtime = generation_started.elapsed();
            let cracked_password_pattern = cracked_password_pattern(result.rank, &candidates);
            let matched_search_phase = cracked_password_pattern
                .as_ref()
                .map(|pattern| pattern.source_phase.clone());

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
                search_space_size: result.candidates_submitted,
                candidates_generated: result.candidates_submitted,
                actual_candidates_evaluated: result.candidates_evaluated,
                cracked: result.cracked,
                rank: result.rank,
                cracked_password_pattern,
                matched_search_phase,
                time_to_first_match_seconds: result.cracked.then(|| seconds(total_runtime)),
                total_runtime_seconds: seconds(total_runtime),
                generation_time_seconds: seconds(generation_time),
                verification_time_seconds: seconds(result.time_taken),
                configured_threads: result.configured_threads,
                active_worker_threads: result.active_worker_threads,
                available_logical_cpus: num_cpus::get().max(1),
                threads_utilization: thread_utilization(
                    result.active_worker_threads,
                    result.configured_threads,
                ),
                candidate_throughput: throughput(result.candidates_evaluated, result.time_taken),
                generation_throughput: throughput(result.candidates_submitted, generation_time),
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
        let mut verification_metrics = AggregateVerificationMetrics::new(configured_threads);
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
                    verification_metrics,
                    false,
                    None,
                    None,
                    generation_started,
                    total_verification_time,
                );
                return;
            }
            let batch_len = candidates.len();

            // 3. Crack batch
            let result = crack_passwords_multithread(
                &candidates,
                hash_to_crack.clone(),
                algo,
                Some(configured_threads),
            );
            verification_metrics.record_batch(
                result.candidates_submitted,
                result.candidates_evaluated,
                result.active_worker_threads,
            );
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
                let global_rank = result
                    .rank
                    .map(|rank| verification_metrics.candidates_generated - batch_len + rank);
                write_infinite_run_record(
                    &matches,
                    hash_to_crack,
                    algo,
                    &persona_json,
                    &llm_model_id,
                    &llm_raw_output,
                    &search_space,
                    verification_metrics,
                    true,
                    global_rank,
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
    metrics: AggregateVerificationMetrics,
    cracked: bool,
    batch_rank: Option<usize>,
    cracked_password_pattern: Option<CrackedPasswordPattern>,
    run_started: Instant,
    verification_time: std::time::Duration,
) {
    let total_runtime = run_started.elapsed();
    let generation_time = total_runtime.saturating_sub(verification_time);
    let matched_search_phase = cracked_password_pattern
        .as_ref()
        .map(|pattern| pattern.source_phase.clone());
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
        search_space_size: metrics.candidates_generated,
        candidates_generated: metrics.candidates_generated,
        actual_candidates_evaluated: metrics.actual_candidates_evaluated,
        cracked,
        rank: batch_rank,
        cracked_password_pattern,
        matched_search_phase,
        time_to_first_match_seconds: cracked.then(|| seconds(total_runtime)),
        total_runtime_seconds: seconds(total_runtime),
        generation_time_seconds: seconds(generation_time),
        verification_time_seconds: seconds(verification_time),
        configured_threads: metrics.configured_threads,
        active_worker_threads: metrics.peak_active_worker_threads,
        available_logical_cpus: num_cpus::get().max(1),
        threads_utilization: thread_utilization(
            metrics.peak_active_worker_threads,
            metrics.configured_threads,
        ),
        candidate_throughput: throughput(metrics.actual_candidates_evaluated, verification_time),
        generation_throughput: throughput(metrics.candidates_generated, generation_time),
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
fn run_python_ai(input_file: &Path, max_token_slots: usize) -> std::io::Result<GenerationContext> {
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

    cmd.arg("ai_logic/main.py")
        .arg("--input")
        .arg(input_file)
        .arg("--max-token-slots")
        .arg(max_token_slots.to_string());

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
    parse_generation_context(stdout.trim(), max_token_slots)
}

fn parse_generation_context(
    stdout: &str,
    max_token_slots: usize,
) -> std::io::Result<GenerationContext> {
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
        .validate_with_max_token_slots(max_token_slots)
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

fn thread_utilization(active_worker_threads: usize, configured_threads: usize) -> f64 {
    if configured_threads == 0 {
        0.0
    } else {
        active_worker_threads as f64 / configured_threads as f64
    }
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

    use super::{
        AggregateVerificationMetrics, DEFAULT_MAX_TOKEN_SLOTS, cracked_password_pattern,
        parse_generation_context, ranked_lengths, thread_utilization,
    };
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
            DEFAULT_MAX_TOKEN_SLOTS,
        )
        .unwrap();

        assert_eq!(context.persona_json["persona"]["name"], "Dan");
        assert_eq!(context.llm_model_id, "test-model");
        assert_eq!(context.llm_raw_output, "raw model output");
        assert_eq!(context.search_space.primary_tokens, vec!["Dan"]);
    }

    #[test]
    fn model_generation_envelope_honors_the_selected_token_slot_cap() {
        let envelope = r#"{
            "persona_json": {"persona": {"name": "Dan"}},
            "llm_model_id": "test-model",
            "llm_raw_output": "raw model output",
            "search_space": {
                "primary_tokens": ["A", "B", "C"],
                "secondary_tokens": [],
                "important_numbers": [],
                "preferred_symbols": [],
                "likely_patterns": ["{token1}{token2}{token3}"],
                "likely_lengths": [4],
                "pattern_weights": {}
            }
        }"#;

        assert!(parse_generation_context(envelope, 3).is_ok());
        assert!(parse_generation_context(envelope, 2).is_err());
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

    #[test]
    fn reports_active_workers_as_a_fraction_of_configured_workers() {
        assert_eq!(thread_utilization(0, 4), 0.0);
        assert_eq!(thread_utilization(3, 4), 0.75);
        assert_eq!(thread_utilization(1, 0), 0.0);
    }

    #[test]
    fn aggregates_generated_and_evaluated_work_independently_across_batches() {
        let mut metrics = AggregateVerificationMetrics::new(4);
        metrics.record_batch(100, 100, 3);
        metrics.record_batch(200, 17, 2);

        assert_eq!(metrics.candidates_generated, 300);
        assert_eq!(metrics.actual_candidates_evaluated, 117);
        assert_eq!(metrics.configured_threads, 4);
        assert_eq!(metrics.peak_active_worker_threads, 3);
    }
}

// fn load_passwords_from_output(output_file: &Path) -> Vec<String> {
//     let file = File::open(output_file).expect("Failed to open generated password file");
//     let reader = BufReader::new(file);
//     reader.lines().filter_map(Result::ok).collect()
// }
