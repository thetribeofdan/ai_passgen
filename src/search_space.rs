use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const ALLOWED_PLACEHOLDERS: [&str; 6] =
    ["token", "token1", "token2", "number", "year", "symbol"];

pub const DEFAULT_ALLOWED_PATTERNS_PATH: &str = "config/allowed_patterns.txt";

/// Runtime-loaded non-symbol base templates for the bounded Rust fallback.
///
/// The file is parsed once at program startup, so researchers can inspect and
/// adjust the fallback set without editing Rust source or rebuilding. Every
/// non-empty, non-comment line must be a unique non-symbol pattern accepted by
/// `is_valid_pattern`. Symbols remain Rust-derived mutations, preserving the
/// global base -> one-symbol -> two-symbol phase order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedPatterns {
    patterns: Vec<String>,
}

impl AllowedPatterns {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let contents = fs::read_to_string(path).map_err(|error| {
            format!(
                "could not read allowed patterns file {}: {error}",
                path.display()
            )
        })?;
        Self::parse(&contents, &path.display().to_string())
    }

    pub fn parse(contents: &str, source: &str) -> Result<Self, String> {
        let mut patterns = Vec::new();

        for (line_index, line) in contents.lines().enumerate() {
            let pattern = line.trim();
            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }
            if !is_valid_pattern(pattern) {
                return Err(format!(
                    "{source}: line {} is not a valid allowed pattern: {pattern}",
                    line_index + 1
                ));
            }
            if pattern.contains("{symbol}") {
                return Err(format!(
                    "{source}: line {} must be a non-symbol base pattern: {pattern}",
                    line_index + 1
                ));
            }
            if patterns.iter().any(|existing| existing == pattern) {
                return Err(format!(
                    "{source}: line {} duplicates allowed pattern: {pattern}",
                    line_index + 1
                ));
            }
            patterns.push(pattern.to_string());
        }

        if patterns.is_empty() {
            return Err(format!(
                "{source}: allowed patterns file contains no patterns"
            ));
        }

        Ok(Self { patterns })
    }

    pub fn as_slice(&self) -> &[String] {
        &self.patterns
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }
}

pub fn default_allowed_patterns_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_ALLOWED_PATTERNS_PATH)
}

/// Rust-owned punctuation alphabet used by the symbol-mutation phase.
///
/// The configured symbol list is compiled into the binary, so expansion does
/// not depend on the process working directory or on a model suggesting a
/// symbol. The model's preferred symbols are still tried before this list.
pub fn rust_symbols() -> Vec<String> {
    let mut symbols = Vec::new();
    for symbol in include_str!("../config/symbols.txt").lines().map(str::trim) {
        if symbol.chars().count() == 1
            && symbol
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_punctuation())
            && !symbols.iter().any(|existing| existing == symbol)
        {
            symbols.push(symbol.to_string());
        }
    }
    symbols
}

/// Rust-owned numeric values used after model-provided numbers and their
/// derived year fragments. Like the symbol alphabet, this list is compiled
/// into the binary so a model omission does not leave numeric patterns empty.
///
/// The file is intentionally bounded to digit-only values of up to four
/// characters. Its order is meaningful: earlier entries are attempted first.
pub fn rust_numbers() -> Vec<String> {
    let mut numbers = Vec::new();
    for number in include_str!("../config/numbers.txt").lines().map(str::trim) {
        if (1..=4).contains(&number.len())
            && number.bytes().all(|character| character.is_ascii_digit())
            && !numbers.iter().any(|existing| existing == number)
        {
            numbers.push(number.to_string());
        }
    }
    numbers
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SearchSpace {
    pub primary_tokens: Vec<String>,
    pub secondary_tokens: Vec<String>,
    pub important_numbers: Vec<String>,
    pub preferred_symbols: Vec<String>,
    pub likely_patterns: Vec<String>,
    #[serde(default)]
    pub likely_lengths: Vec<usize>,
    #[serde(default)]
    pub pattern_weights: HashMap<String, f32>,
}

impl SearchSpace {
    pub fn validate(mut self) -> Result<Self, String> {
        normalize_values(&mut self.primary_tokens);
        normalize_values(&mut self.secondary_tokens);
        normalize_values(&mut self.important_numbers);
        normalize_values(&mut self.preferred_symbols);
        normalize_values(&mut self.likely_patterns);
        let mut unique_lengths = Vec::with_capacity(self.likely_lengths.len());
        for length in self.likely_lengths.drain(..) {
            if !unique_lengths.contains(&length) {
                unique_lengths.push(length);
            }
        }
        self.likely_lengths = unique_lengths;

        if self.primary_tokens.is_empty() && self.secondary_tokens.is_empty() {
            return Err("search space must contain at least one token".to_string());
        }

        if self.preferred_symbols.iter().any(|symbol| {
            symbol.chars().count() != 1
                || !symbol
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_punctuation())
        }) {
            return Err(
                "preferred_symbols entries must contain one ASCII punctuation character"
                    .to_string(),
            );
        }

        if self
            .likely_patterns
            .iter()
            .any(|pattern| !is_valid_pattern(pattern))
        {
            return Err("likely_patterns contains an invalid placeholder".to_string());
        }

        if self
            .likely_lengths
            .iter()
            .any(|length| !(4..=32).contains(length))
        {
            return Err("likely_lengths must be between 4 and 32".to_string());
        }

        if self.pattern_weights.iter().any(|(pattern, weight)| {
            !self.likely_patterns.contains(pattern)
                || !is_valid_pattern(pattern)
                || !weight.is_finite()
                || !(0.0..=1.0).contains(weight)
        }) {
            return Err(
                "pattern_weights must reference a likely pattern and contain a finite weight from 0 to 1"
                    .to_string(),
            );
        }

        Ok(self)
    }
}

pub fn is_valid_pattern(pattern: &str) -> bool {
    let Some(parts) = pattern_parts(pattern) else {
        return false;
    };
    let token_count = parts
        .iter()
        .filter(|placeholder| placeholder.starts_with("token"))
        .count();
    let number_count = parts
        .iter()
        .filter(|placeholder| matches!(**placeholder, "number" | "year"))
        .count();
    let symbol_count = parts
        .iter()
        .filter(|placeholder| **placeholder == "symbol")
        .count();

    (1..=2).contains(&token_count) && number_count <= 1 && symbol_count <= 2 && parts.len() <= 5
}

/// Insert one `{symbol}` placeholder at every component boundary in a valid
/// non-symbol pattern. This is the first Rust-derived mutation family.
pub fn rust_derived_symbol_mutations(pattern: &str) -> Vec<String> {
    let Some(parts) = pattern_parts(pattern) else {
        return Vec::new();
    };
    if !is_valid_pattern(pattern) || parts.iter().any(|placeholder| *placeholder == "symbol") {
        return Vec::new();
    }

    let mut mutations = Vec::with_capacity(parts.len() + 1);
    for insertion_point in 0..=parts.len() {
        mutations.push(pattern_with_symbol_insertions(&parts, &[insertion_point]));
    }
    mutations
}

/// Insert two `{symbol}` placeholders at every pair of component boundaries
/// in a valid non-symbol pattern. Distinct boundaries are emitted first, then
/// adjacent pairs at the same boundary. The two placeholder occurrences are
/// expanded independently by the Rust expander.
pub fn rust_derived_two_symbol_mutations(pattern: &str) -> Vec<String> {
    let Some(parts) = pattern_parts(pattern) else {
        return Vec::new();
    };
    if !is_valid_pattern(pattern) || parts.iter().any(|placeholder| *placeholder == "symbol") {
        return Vec::new();
    }

    let boundary_count = parts.len() + 1;
    let mut mutations = Vec::with_capacity(boundary_count * (boundary_count + 1) / 2);

    for first_insertion_point in 0..boundary_count {
        for second_insertion_point in (first_insertion_point + 1)..boundary_count {
            mutations.push(pattern_with_symbol_insertions(
                &parts,
                &[first_insertion_point, second_insertion_point],
            ));
        }
    }
    for insertion_point in 0..boundary_count {
        mutations.push(pattern_with_symbol_insertions(
            &parts,
            &[insertion_point, insertion_point],
        ));
    }

    mutations
}

fn pattern_with_symbol_insertions(parts: &[&str], insertion_points: &[usize]) -> String {
    let mut mutation = String::new();
    for boundary in 0..=parts.len() {
        for insertion_point in insertion_points {
            if *insertion_point == boundary {
                mutation.push_str("{symbol}");
            }
        }
        if let Some(placeholder) = parts.get(boundary) {
            mutation.push('{');
            mutation.push_str(placeholder);
            mutation.push('}');
        }
    }
    mutation
}

fn pattern_parts(pattern: &str) -> Option<Vec<&str>> {
    if pattern.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    let mut remainder = pattern;
    while !remainder.is_empty() {
        let after_open = remainder.strip_prefix('{')?;
        let end = after_open.find('}')?;
        let placeholder = &after_open[..end];
        if !ALLOWED_PLACEHOLDERS.contains(&placeholder) {
            return None;
        }
        parts.push(placeholder);
        remainder = &after_open[end + 1..];
    }
    (!parts.is_empty()).then_some(parts)
}

fn normalize_values(values: &mut Vec<String>) {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        let value = value.trim().to_string();
        if !value.is_empty() && !normalized.contains(&value) {
            normalized.push(value);
        }
    }
    *values = normalized;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        AllowedPatterns, SearchSpace, default_allowed_patterns_path, is_valid_pattern,
        rust_derived_symbol_mutations, rust_derived_two_symbol_mutations, rust_numbers,
        rust_symbols,
    };

    #[test]
    fn deserializes_and_normalizes_schema_values() {
        let search_space = serde_json::from_str::<SearchSpace>(
            r#"{
                "primary_tokens": [" Dan ", "Dan", ""],
                "secondary_tokens": [],
                "important_numbers": ["1999"],
                "preferred_symbols": ["!", "!"],
                "likely_patterns": ["{token}{year}"],
                "likely_lengths": [10],
                "pattern_weights": {"{token}{year}": 0.8}
            }"#,
        )
        .unwrap()
        .validate()
        .unwrap();

        assert_eq!(search_space.primary_tokens, vec!["Dan"]);
        assert_eq!(search_space.preferred_symbols, vec!["!"]);
        assert_eq!(search_space.likely_lengths, vec![10]);
    }

    #[test]
    fn rejects_unknown_fields_and_invalid_patterns() {
        let unknown_field = serde_json::from_str::<SearchSpace>(
            r#"{
                "primary_tokens": ["Dan"],
                "secondary_tokens": [],
                "important_numbers": [],
                "preferred_symbols": [],
                "likely_patterns": ["{token}{year}"],
                "passwords": ["Dan1999"]
            }"#,
        );
        assert!(unknown_field.is_err());

        let unsupported = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec![],
            likely_patterns: vec!["{random}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        assert!(unsupported.validate().is_err());
    }

    #[test]
    fn permits_an_empty_model_phase_for_rust_fallback() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec![],
            likely_patterns: vec![],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        }
        .validate()
        .unwrap();

        assert!(search_space.likely_patterns.is_empty());
    }

    #[test]
    fn enforces_the_bounded_placeholder_grammar() {
        assert!(is_valid_pattern("{token}{symbol}{token}{year}"));
        assert!(is_valid_pattern("{token1}{symbol}{token2}{symbol}{number}"));
        assert!(!is_valid_pattern("prefix{token}"));
        assert!(!is_valid_pattern("{token}{number}{year}"));
        assert!(!is_valid_pattern("{token}{symbol}{symbol}{symbol}"));
        assert!(!is_valid_pattern("{token}{token1}{number}{symbol}{token2}"));
    }

    #[test]
    fn derives_symbol_templates_at_every_component_boundary() {
        let mutations = rust_derived_symbol_mutations("{token1}{token2}{number}");

        assert_eq!(
            mutations,
            vec![
                "{symbol}{token1}{token2}{number}",
                "{token1}{symbol}{token2}{number}",
                "{token1}{token2}{symbol}{number}",
                "{token1}{token2}{number}{symbol}",
            ]
        );
        assert!(rust_symbols().contains(&"!".to_string()));
    }

    #[test]
    fn derives_two_symbol_templates_at_every_boundary_pair() {
        let mutations = rust_derived_two_symbol_mutations("{token1}{token2}{number}");

        assert_eq!(
            mutations,
            vec![
                "{symbol}{token1}{symbol}{token2}{number}",
                "{symbol}{token1}{token2}{symbol}{number}",
                "{symbol}{token1}{token2}{number}{symbol}",
                "{token1}{symbol}{token2}{symbol}{number}",
                "{token1}{symbol}{token2}{number}{symbol}",
                "{token1}{token2}{symbol}{number}{symbol}",
                "{symbol}{symbol}{token1}{token2}{number}",
                "{token1}{symbol}{symbol}{token2}{number}",
                "{token1}{token2}{symbol}{symbol}{number}",
                "{token1}{token2}{number}{symbol}{symbol}",
            ]
        );
    }

    #[test]
    fn loads_configured_generic_numbers() {
        let numbers = rust_numbers();

        assert!(numbers.contains(&"123".to_string()));
        assert!(numbers.iter().all(|number| {
            (1..=4).contains(&number.len())
                && number.bytes().all(|character| character.is_ascii_digit())
        }));
    }

    #[test]
    fn parses_allowed_patterns_in_file_order() {
        let patterns = AllowedPatterns::parse(
            "\n# Bounded fallback grammar\n  {token}{number}  \n{token}\n",
            "test patterns",
        )
        .unwrap();

        assert_eq!(
            patterns.as_slice(),
            &["{token}{number}".to_string(), "{token}".to_string()]
        );
    }

    #[test]
    fn rejects_invalid_symbol_duplicate_and_empty_allowed_patterns() {
        let invalid = AllowedPatterns::parse("{token}{unknown}\n", "test patterns").unwrap_err();
        assert!(invalid.contains("line 1"));

        let symbol = AllowedPatterns::parse("{token}{symbol}\n", "test patterns").unwrap_err();
        assert!(symbol.contains("non-symbol base pattern"));

        let duplicate = AllowedPatterns::parse("{token}\n{token}\n", "test patterns").unwrap_err();
        assert!(duplicate.contains("duplicates"));

        let empty = AllowedPatterns::parse("# comment only\n\n", "test patterns").unwrap_err();
        assert!(empty.contains("contains no patterns"));
    }

    #[test]
    fn loads_the_default_allowed_patterns_configuration_in_order() {
        let patterns = AllowedPatterns::from_file(&default_allowed_patterns_path()).unwrap();

        assert_eq!(
            patterns.as_slice(),
            &[
                "{token}".to_string(),
                "{token}{number}".to_string(),
                "{number}{token}".to_string(),
                "{token}{year}".to_string(),
                "{year}{token}".to_string(),
                "{token1}{token2}".to_string(),
                "{token}{token}".to_string(),
                "{token1}{token2}{number}".to_string(),
                "{token1}{number}{token2}".to_string(),
                "{number}{token1}{token2}".to_string(),
                "{token1}{token2}{year}".to_string(),
                "{token1}{year}{token2}".to_string(),
                "{year}{token1}{token2}".to_string(),
            ]
        );
    }

    #[test]
    fn reports_the_requested_path_when_allowed_patterns_file_is_missing() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let missing_path = std::env::temp_dir().join(format!(
            "ai-passgen-missing-allowed-patterns-{}-{unique}.txt",
            std::process::id()
        ));

        let error = AllowedPatterns::from_file(&missing_path).unwrap_err();

        assert!(error.contains("could not read allowed patterns file"));
        assert!(error.contains(&missing_path.display().to_string()));
    }
}
