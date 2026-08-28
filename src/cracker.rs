use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use bcrypt::verify as bcrypt_verify;
use md5;
use num_cpus;
use rayon::prelude::*;
use sha2::{Digest, Sha256, Sha512};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Result of a cracking attempt.
pub struct CrackResult {
    pub cracked: bool,
    pub matched_password: Option<String>,
    pub matched_hash: Option<String>,
    pub time_taken: Duration,
    pub rank: Option<usize>,
    /// Candidates handed to this verifier batch.
    pub candidates_submitted: usize,
    /// Exact number of hash-verification predicate calls that started.
    /// A parallel `find_any` can leave other calls in flight after a match.
    pub candidates_evaluated: usize,
    /// Rayon workers requested for this verifier batch after normalisation.
    pub configured_threads: usize,
    /// Rayon workers that evaluated at least one candidate in this batch.
    pub active_worker_threads: usize,
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
pub fn crack_passwords_multithread<T>(
    passwords: &[T],
    target_hash: String,
    algo: &str,
    max_threads: Option<usize>,
) -> CrackResult
where
    T: AsRef<str> + Sync,
{
    let configured_threads = max_threads.unwrap_or_else(num_cpus::get).max(1);
    let normalized_algo = algo.trim().to_ascii_lowercase();
    let normalized_hash = if matches!(normalized_algo.as_str(), "md5" | "sha256" | "sha512") {
        target_hash.trim().to_ascii_lowercase()
    } else {
        target_hash.trim().to_string()
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(configured_threads)
        .build()
        .expect("Failed to build Rayon thread pool");

    let start = Instant::now();

    let candidates_submitted = passwords.len();
    let candidates_evaluated = AtomicUsize::new(0);
    let active_workers = (0..pool.current_num_threads())
        .map(|_| AtomicBool::new(false))
        .collect::<Vec<_>>();
    let found: Option<(usize, String)> = pool.install(|| {
        passwords
            .par_iter()
            .enumerate()
            .find_any(|(_, candidate)| {
                candidates_evaluated.fetch_add(1, Ordering::Relaxed);
                if let Some(worker_index) = rayon::current_thread_index()
                    && let Some(worker) = active_workers.get(worker_index)
                {
                    worker.store(true, Ordering::Relaxed);
                }
                is_password_match(candidate.as_ref(), &normalized_hash, &normalized_algo)
            })
            .map(|(index, candidate)| (index + 1, candidate.as_ref().to_string()))
    });

    let duration = start.elapsed();
    let active_worker_threads = active_workers
        .iter()
        .filter(|worker| worker.load(Ordering::Relaxed))
        .count();
    let candidates_evaluated = candidates_evaluated.load(Ordering::Relaxed);

    if let Some((rank, password)) = found {
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
            rank: Some(rank),
            candidates_submitted,
            candidates_evaluated,
            configured_threads,
            active_worker_threads,
        }
    } else {
        CrackResult {
            cracked: false,
            matched_password: None,
            matched_hash: None,
            time_taken: duration,
            rank: None,
            candidates_submitted,
            candidates_evaluated,
            configured_threads,
            active_worker_threads,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{crack_passwords_multithread, is_supported_algorithm};

    #[test]
    fn verifies_md5_and_normalizes_inputs() {
        let candidates = vec!["wrong".to_string(), "secret".to_string()];
        let result = crack_passwords_multithread(
            &candidates,
            "5EBE2294ECD0E0F08EAB7690D2A6EE69".to_string(),
            " MD5 ",
            Some(0),
        );

        assert!(result.cracked);
        assert_eq!(result.matched_password.as_deref(), Some("secret"));
        assert_eq!(result.candidates_submitted, 2);
        assert_eq!(result.candidates_evaluated, 2);
        assert_eq!(result.configured_threads, 1);
        assert_eq!(result.active_worker_threads, 1);
    }

    #[test]
    fn recognizes_only_supported_algorithms() {
        assert!(is_supported_algorithm("sha256"));
        assert!(!is_supported_algorithm("sha1"));
    }

    #[test]
    fn records_actual_work_for_exhausted_and_empty_batches() {
        let candidates = vec!["one".to_string(), "two".to_string()];
        let exhausted = crack_passwords_multithread(
            &candidates,
            "5EBE2294ECD0E0F08EAB7690D2A6EE69".to_string(),
            "md5",
            Some(2),
        );

        assert!(!exhausted.cracked);
        assert_eq!(exhausted.candidates_submitted, 2);
        assert_eq!(exhausted.candidates_evaluated, 2);
        assert!((1..=2).contains(&exhausted.active_worker_threads));

        let empty: Vec<String> = Vec::new();
        let empty_result = crack_passwords_multithread(
            &empty,
            "5EBE2294ECD0E0F08EAB7690D2A6EE69".to_string(),
            "md5",
            Some(2),
        );
        assert_eq!(empty_result.candidates_submitted, 0);
        assert_eq!(empty_result.candidates_evaluated, 0);
        assert_eq!(empty_result.active_worker_threads, 0);
    }
}
