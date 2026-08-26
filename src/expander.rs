use std::collections::HashSet;

use crate::search_space::SearchSpace;

pub fn expand_candidates(search_space: &SearchSpace, length: usize, amount: usize) -> Vec<String> {
    let mut candidates = Vec::with_capacity(amount);
    let mut seen = HashSet::with_capacity(amount);
    let mut tokens = search_space.primary_tokens.clone();
    tokens.extend(search_space.secondary_tokens.iter().cloned());
    tokens.retain(|token| !token.is_empty());

    let numbers = if search_space.important_numbers.is_empty() {
        vec![String::new()]
    } else {
        search_space.important_numbers.clone()
    };
    let symbols = if search_space.preferred_symbols.is_empty() {
        vec![String::new()]
    } else {
        search_space.preferred_symbols.clone()
    };
    let patterns = if search_space.likely_patterns.is_empty() {
        vec!["{token}{number}".to_string()]
    } else {
        search_space.likely_patterns.clone()
    };

    for pattern in patterns {
        for first in &tokens {
            for second in &tokens {
                for number in &numbers {
                    for symbol in &symbols {
                        let values = [
                            ("{token}", first.as_str()),
                            ("{token1}", first.as_str()),
                            ("{token2}", second.as_str()),
                            ("{number}", number.as_str()),
                            ("{year}", number.as_str()),
                            ("{symbol}", symbol.as_str()),
                        ];
                        let mut candidate = pattern.clone();
                        for (placeholder, value) in values {
                            candidate = candidate.replace(placeholder, value);
                        }

                        for variant in case_variants(&candidate) {
                            if variant.chars().count() == length && seen.insert(variant.clone()) {
                                candidates.push(variant);
                                if candidates.len() == amount {
                                    return candidates;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    candidates
}

fn case_variants(candidate: &str) -> Vec<String> {
    let mut variants = vec![
        candidate.to_string(),
        candidate.to_lowercase(),
        candidate.to_uppercase(),
    ];
    let mut capitalized = candidate.to_lowercase();
    if let Some(first) = capitalized.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    variants.push(capitalized);
    variants
}

#[cfg(test)]
mod tests {
    use super::expand_candidates;
    use crate::search_space::SearchSpace;

    #[test]
    fn expands_patterns_and_deduplicates() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["1999".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token}{year}".to_string()],
        };

        let candidates = expand_candidates(&search_space, 7, 10);
        assert_eq!(candidates, vec!["Dan1999", "dan1999", "DAN1999"]);
    }
}
