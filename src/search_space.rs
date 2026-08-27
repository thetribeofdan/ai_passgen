use std::collections::HashMap;

use serde::Deserialize;

pub const ALLOWED_PATTERNS: [&str; 7] = [
    "{token}{year}",
    "{token}{number}",
    "{token}{symbol}{number}",
    "{token1}{token2}{number}",
    "{token}{symbol}{token}{year}",
    "{token}{number}{symbol}",
    "{token}{symbol}{year}",
];

#[derive(Debug, Deserialize, PartialEq)]
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

        if self
            .preferred_symbols
            .iter()
            .any(|symbol| symbol.chars().count() != 1 || !symbol.is_ascii())
        {
            return Err("preferred_symbols entries must contain one ASCII character".to_string());
        }

        if self
            .likely_patterns
            .iter()
            .any(|pattern| !ALLOWED_PATTERNS.contains(&pattern.as_str()))
        {
            return Err("likely_patterns contains an unsupported pattern".to_string());
        }

        if self.likely_patterns.is_empty() {
            return Err("search space must contain at least one supported pattern".to_string());
        }

        if self
            .likely_lengths
            .iter()
            .any(|length| !(4..=32).contains(length))
        {
            return Err("likely_lengths must be between 4 and 32".to_string());
        }

        if self.pattern_weights.iter().any(|(pattern, weight)| {
            !ALLOWED_PATTERNS.contains(&pattern.as_str())
                || !weight.is_finite()
                || !(0.0..=1.0).contains(weight)
        }) {
            return Err("pattern_weights contains an invalid pattern or weight".to_string());
        }

        Ok(self)
    }
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

    use super::SearchSpace;

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
    fn rejects_unknown_fields_and_unsupported_patterns() {
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
}
