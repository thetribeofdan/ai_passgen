// src/hash_detect.rs

/// Full hash auto-detection (bcrypt, argon2, PBKDF2, Unix crypt,
/// raw SHA, MD5, NTLM, MySQL, LDAP style, etc.)
///
/// Returns the *best guess* for the hash type.
pub fn detect_hash_algo(hash: &str) -> &'static str {
    let h = hash.trim();

    // ------------------------------
    // 1. Prefix-based hash detection
    // ------------------------------

    // BCRYPT
    if h.starts_with("$2a$") || h.starts_with("$2b$") || h.starts_with("$2y$") {
        return "bcrypt";
    }

    // ARGON2
    if h.starts_with("$argon2i$")
        || h.starts_with("$argon2d$")
        || h.starts_with("$argon2id$")
    {
        return "argon2";
    }

    // PBKDF2 (Django, some enterprise systems)
    if h.starts_with("pbkdf2_sha256$")
        || h.starts_with("pbkdf2_sha1$")
        || h.starts_with("pbkdf2_sha512$")
    {
        return "pbkdf2";
    }

    // UNIX crypt hashes
    if h.starts_with("$1$") {
        return "md5_crypt"; // MD5-crypt
    }
    if h.starts_with("$5$") {
        return "sha256_crypt"; // SHA256-crypt
    }
    if h.starts_with("$6$") {
        return "sha512_crypt"; // SHA512-crypt
    }

    // LDAP SSHA
    if h.starts_with("{SSHA}") || h.starts_with("{ssha}") {
        return "ssha";
    }

    // ------------------------------
    // 2. Database hash formats
    // ------------------------------

    // MySQL (old)
    if h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return "mysql-old";
    }

    // MySQL (new SHA1)
    if h.len() == 40 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return "mysql-sha1";
    }

    // PostgreSQL style?
    if h.starts_with("md5") && h.len() == 35 {
        return "postgresql-md5";
    }

    // NTLM (32 hex chars)
    if h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        // Could be MD5, but NTLM also fits — JTR treats this specially.
        return "ntlm_or_md5";
    }

    // ------------------------------
    // 3. Raw hash length inference
    // ------------------------------

    // Raw MD5
    if h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return "md5";
    }

    // Raw SHA1
    if h.len() == 40 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha1";
    }

    // Raw SHA256
    if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha256";
    }

    // Raw SHA512
    if h.len() == 128 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha512";
    }

    // ------------------------------
    // 4. Fallback default
    // ------------------------------

    "sha256"
}
