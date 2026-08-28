// src/hash_detect.rs

/// Detect the hash formats currently supported by the verifier.
///
/// Ambiguous raw hexadecimal formats are reported using the most common
/// supported interpretation. Use `--algo` when the source format is known.
pub fn detect_hash_algo(hash: &str) -> &'static str {
    let h = hash.trim();

    if h.starts_with("$2a$") || h.starts_with("$2b$") || h.starts_with("$2y$") {
        return "bcrypt";
    }

    if h.starts_with("$argon2i$") || h.starts_with("$argon2d$") || h.starts_with("$argon2id$") {
        return "argon2";
    }

    if h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return "md5";
    }

    if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha256";
    }

    if h.len() == 128 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha512";
    }

    "unsupported"
}

#[cfg(test)]
mod tests {
    use super::detect_hash_algo;

    #[test]
    fn detects_supported_formats() {
        assert_eq!(detect_hash_algo("$2b$12$abcdefghijklmnopqrstuu"), "bcrypt");
        assert_eq!(
            detect_hash_algo("$argon2id$v=19$m=1,t=1,p=1$YWJj$ZA"),
            "argon2"
        );
        assert_eq!(detect_hash_algo(&"a".repeat(32)), "md5");
        assert_eq!(detect_hash_algo(&"a".repeat(64)), "sha256");
        assert_eq!(detect_hash_algo(&"a".repeat(128)), "sha512");
        assert_eq!(detect_hash_algo("not-a-supported-hash"), "unsupported");
    }
}
