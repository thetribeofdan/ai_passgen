use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use bcrypt::verify as bcrypt_verify;
use md5;
use num_cpus;
use rayon::prelude::*;
use sha2::{Digest, Sha256, Sha512};
use std::time::{Duration, Instant};

/// Result of a cracking attempt.
pub struct CrackResult {
    pub cracked: bool,
    pub matched_password: Option<String>,
    pub matched_hash: Option<String>,
    pub time_taken: Duration,
}

/// Hashes a password using a "fast" digest (sha256/sha512/md5).
/// Returns None for algorithms that are not supported here.
fn hash_fast(password: &str, algo: &str) -> Option<String> {
    match algo {
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            Some(format!("{:x}", hasher.finalize()))
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(password.as_bytes());
            Some(format!("{:x}", hasher.finalize()))
        }
        "md5" => Some(format!("{:x}", md5::compute(password.as_bytes()))),
        _ => None,
    }
}

/// Checks whether a candidate password matches the target hash,
/// using the appropriate algorithm.
fn is_password_match(password: &str, target_hash: &str, algo: &str) -> bool {
    match algo.trim().to_ascii_lowercase().as_str() {
        "sha256" | "sha512" | "md5" => {
            if let Some(computed) = hash_fast(password, algo) {
                computed == target_hash
            } else {
                false
            }
        }
        "bcrypt" => {
            // bcrypt hashes embed salt and cost inside target_hash.
            bcrypt_verify(password, target_hash).unwrap_or(false)
        }
        "argon2" => {
            if let Ok(parsed) = PasswordHash::new(target_hash) {
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            } else {
                false
            }
        }
        // You can add more here (pbkdf2, etc.)
        _ => false,
    }
}

pub fn is_supported_algorithm(algo: &str) -> bool {
    match algo.trim().to_ascii_lowercase().as_str() {
        "md5" | "sha256" | "sha512" | "bcrypt" | "argon2" => true,
        _ => false,
    }
}

/// Multithreaded cracking engine.
/// - passwords: candidate plaintexts
/// - target_hash: the hash we want to crack
/// - algo: which hash algorithm to use (sha256, bcrypt, argon2, etc.)
/// - max_threads: optional override for Rayon threadpool size
pub fn crack_passwords_multithread(
    passwords: Vec<String>,
    target_hash: String,
    algo: &str,
    max_threads: Option<usize>,
) -> CrackResult {
    let threads = max_threads.unwrap_or_else(num_cpus::get).max(1);
    let normalized_algo = algo.trim().to_ascii_lowercase();
    let normalized_hash = if matches!(normalized_algo.as_str(), "md5" | "sha256" | "sha512") {
        target_hash.trim().to_ascii_lowercase()
    } else {
        target_hash.trim().to_string()
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("Failed to build Rayon thread pool");

    let start = Instant::now();

    let found: Option<String> = pool.install(|| {
        passwords
            .par_iter()
            .find_any(|candidate| is_password_match(candidate, &normalized_hash, &normalized_algo))
            .map(|s| s.to_string())
    });

    let duration = start.elapsed();

    if let Some(password) = found {
        // For reporting: compute hash again for "fast" algorithms,
        // or just reuse target_hash for salted algorithms.
        let matched_hash = match normalized_algo.as_str() {
            "sha256" | "sha512" | "md5" => {
                hash_fast(&password, &normalized_algo).unwrap_or_else(|| normalized_hash.clone())
            }
            "bcrypt" | "argon2" => normalized_hash.clone(),
            _ => normalized_hash.clone(),
        };

        CrackResult {
            cracked: true,
            matched_password: Some(password),
            matched_hash: Some(matched_hash),
            time_taken: duration,
        }
    } else {
        CrackResult {
            cracked: false,
            matched_password: None,
            matched_hash: None,
            time_taken: duration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{crack_passwords_multithread, is_supported_algorithm};

    #[test]
    fn verifies_md5_and_normalizes_inputs() {
        let result = crack_passwords_multithread(
            vec!["wrong".to_string(), "secret".to_string()],
            "5EBE2294ECD0E0F08EAB7690D2A6EE69".to_string(),
            " MD5 ",
            Some(0),
        );

        assert!(result.cracked);
        assert_eq!(result.matched_password.as_deref(), Some("secret"));
    }

    #[test]
    fn recognizes_only_supported_algorithms() {
        assert!(is_supported_algorithm("sha256"));
        assert!(!is_supported_algorithm("sha1"));
    }
}
