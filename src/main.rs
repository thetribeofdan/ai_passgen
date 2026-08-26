use chrono::Local;
use clap::{Arg, Command};
use rand::thread_rng;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
mod cracker;
use crate::cracker::crack_passwords_multithread;
use num_cpus;
mod hash_detect;
use crate::hash_detect::detect_hash_algo;
use rand::Rng;
mod expander;
mod search_space;
use crate::expander::expand_candidates;
use crate::search_space::SearchSpace;

/// ------------------------------------------------------------
/// MAIN
/// ------------------------------------------------------------
fn main() {
    let matches = Command::new("Password Generator")
        .version("1.5.0")
        .author("Daniel Egbeleke")
        .about("Generates AI-influenced passwords and optionally attempts to crack a provided hash.")
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
                .help("Length of each generated password (default: 10)")
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
        .get_matches();

    // Resolve input file
    let input_path = matches
        .get_one::<String>("input")
        .map(PathBuf::from)
        .unwrap_or_else(|| get_default_persona_file());

    if !input_path.exists() {
        eprintln!("Error: input file not found: {:?}", input_path);
        std::process::exit(1);
    }

    // Resolve output path
    let output_path = matches
        .get_one::<String>("output")
        .map(PathBuf::from)
        .unwrap_or_else(|| generate_default_output_path(&input_path));

    let length = matches
        .get_one::<String>("length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10);

    let amount = matches
        .get_one::<String>("amount")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(20);

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).expect("Failed to create output directory");
    }

    // ------------------------------------------------------------
    // STEP 1 — Generate passwords (AI or fallback)
    // ------------------------------------------------------------
    let search_space = match run_python_ai(
        &input_path,
        length,
        amount,
        matches.get_one::<String>("algo").map(|s| s.as_str()),
        matches
            .get_one::<String>("threads")
            .and_then(|v| v.parse().ok()),
    ) {
        Ok(search_space) => search_space,
        Err(e) => {
            eprintln!(
                "AI search-space generation failed: {e}\nFalling back to random Rust generator..."
            );
            let mut file = File::create(&output_path).expect("Failed to create output file");

            for _ in 0..amount {
                let password = generate_password(length);
                writeln!(file, "{}", password).expect("Failed to write to file");
            }

            println!(
                "Generated {} fallback passwords (len: {}) → {:?}",
                amount, length, output_path
            );

            return;
        }
    };

    let generated_candidates = expand_candidates(&search_space, length, amount);
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

    // ------------------------------------------------------------
    // STEP 2 — Hash Cracking Mode (Normal + Infinite Cracking)
    // ------------------------------------------------------------
    // ------------------------------------------------------------
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
                println!("Auto-detected hash type: {}", detected);
                detected
            });

        // Detect infinite mode (no amount/length supplied)
        let infinite_mode = matches.get_one::<String>("amount").is_none()
            && matches.get_one::<String>("length").is_none();

        println!("\n=== Crack Mode Enabled ===");
        println!("→ Target Hash: {}", hash_to_crack);
        println!("→ Algorithm: {}", algo);
        println!("→ Threads: {}\n", max_threads.unwrap_or_else(num_cpus::get));

        // --------------------------------------------------------
        // NORMAL MODE (user specified amount or length)
        // --------------------------------------------------------
        if !infinite_mode {
            let passwords = if matches.get_one::<String>("amount").is_some()
                || matches.get_one::<String>("length").is_some()
            {
                expand_candidates(&search_space, length, amount)
            } else {
                match run_python_ai(
                    &input_path,
                    length,
                    amount,
                    matches.get_one::<String>("algo").map(|s| s.as_str()),
                    max_threads,
                ) {
                    Ok(space) => expand_candidates(&space, length, amount),
                    Err(e) => {
                        eprintln!("AI search-space generation failed: {}", e);
                        std::process::exit(1);
                    }
                }
            };

            let result =
                crack_passwords_multithread(passwords, hash_to_crack.clone(), algo, max_threads);

            if result.cracked {
                println!("MATCH FOUND!");
                println!("Password: {}", result.matched_password.unwrap());
                println!("Hash: {}", result.matched_hash.unwrap());
            } else {
                println!("No match found.");
            }

            println!("Time taken: {:?}", result.time_taken);
            return;
        }

        // --------------------------------------------------------
        // INFINITE MODE
        // --------------------------------------------------------
        println!("∞ Infinite cracking mode activated.");
        println!("→ No length/amount were provided.");
        println!("→ System will generate increasing batches until cracked.\n");

        let mut length = 12; // starting length
        let mut batch_size = 100; // starting batch size
        let max_length = 32; // safe upper bound

        loop {
            println!("---");
            println!("Batch attempt:");
            println!("→ Generating {} passwords", batch_size);
            println!("→ Length {}", length);

            // let temp_output = Path::new("output/infinite_run.txt");

            // 1. Generate batch using AI
            let passwords = match run_python_ai(
                &input_path,
                length,
                batch_size,
                matches.get_one::<String>("algo").map(|s| s.as_str()),
                max_threads,
            ) {
                Ok(space) => expand_candidates(&space, length, batch_size),
                Err(e) => {
                    eprintln!("AI batch generation failed: {}", e);
                    std::process::exit(1);
                }
            };

            // 3. Crack batch
            let result =
                crack_passwords_multithread(passwords, hash_to_crack.clone(), algo, max_threads);

            if result.cracked {
                println!("\nMATCH FOUND!");
                println!("Password: {}", result.matched_password.unwrap());
                println!("Hash: {}", result.matched_hash.unwrap());
                println!("Time Taken: {:?}", result.time_taken);
                return;
            }

            println!("No match in this batch. Expanding search...\n");

            // 4. Expand search space
            if length < max_length {
                length += 1; // go deeper
            } else {
                batch_size *= 2; // go wider
            }
        }
    }
}

/// ------------------------------------------------------------
/// PYTHON AI GENERATION
/// ------------------------------------------------------------
fn run_python_ai(
    input_file: &Path,
    length: usize,
    amount: usize,
    algo: Option<&str>, // NEW OPTIONAL FIELDS
    threads: Option<usize>,
) -> std::io::Result<SearchSpace> {
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
        .arg("--length")
        .arg(length.to_string())
        .arg("--amount")
        .arg(amount.to_string());

    // optional parameters
    if let Some(a) = algo {
        cmd.arg("--algo").arg(a);
    }

    if let Some(t) = threads {
        cmd.arg("--threads").arg(t.to_string());
    }

    let output = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;

    if !output.status.success() {
        eprintln!(
            "Python stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Python script failed",
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // println!("Raw Python stdout:\n{}", stdout);

    let search_space: SearchSpace = serde_json::from_str(stdout.trim()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid search-space JSON from Python: {error}"),
        )
    })?;
    search_space
        .validate()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;

    Ok(search_space)
}

/// ------------------------------------------------------------
/// FALLBACK GENERATOR
/// ------------------------------------------------------------
fn generate_password(length: usize) -> String {
    let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    // let mut rng = rand::rng();
    let mut rng = thread_rng();

    (0..length)
        .map(|_| {
            // let idx = rng.random_range(0..charset.len());
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
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

// fn load_passwords_from_output(output_file: &Path) -> Vec<String> {
//     let file = File::open(output_file).expect("Failed to open generated password file");
//     let reader = BufReader::new(file);
//     reader.lines().filter_map(Result::ok).collect()
// }
