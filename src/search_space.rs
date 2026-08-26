use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SearchSpace {
    #[serde(default)]
    pub primary_tokens: Vec<String>,
    #[serde(default)]
    pub secondary_tokens: Vec<String>,
    #[serde(default)]
    pub important_numbers: Vec<String>,
    #[serde(default)]
    pub preferred_symbols: Vec<String>,
    #[serde(default)]
    pub likely_patterns: Vec<String>,
}

impl SearchSpace {
    pub fn validate(&self) -> Result<(), String> {
        let total_tokens = self.primary_tokens.len() + self.secondary_tokens.len();
        if total_tokens == 0 {
            return Err("search space must contain at least one token".to_string());
        }
        if self
            .preferred_symbols
            .iter()
            .any(|symbol| symbol.chars().count() != 1)
        {
            return Err("preferred_symbols entries must contain one character".to_string());
        }
        Ok(())
    }
}
