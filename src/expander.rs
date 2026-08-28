use std::collections::{BTreeSet, HashSet};

use serde::Serialize;

use crate::search_space::{
    AllowedPatterns, SearchSpace, is_valid_pattern_with_max_token_slots,
    rust_derived_symbol_mutations, rust_derived_two_symbol_mutations, rust_numbers, rust_symbols,
    token_slot_index,
};

const PATTERN_PHASE_NAMES: [&str; 6] = [
    "weighted_model",
    "unweighted_model",
    "configured_fallback",
    "generated_fallback",
    "rust_derived_one_symbol",
    "rust_derived_two_symbol",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeneratedCandidate {
    pub password: String,
    pub source_pattern: String,
    pub source_phase: String,
    pub case_variant: String,
}

impl AsRef<str> for GeneratedCandidate {
    fn as_ref(&self) -> &str {
        &self.password
    }
}

pub fn expand_candidates(
    search_space: &SearchSpace,
    allowed_patterns: &AllowedPatterns,
    length: usize,
    amount: usize,
) -> Vec<String> {
    let mut excluded = HashSet::new();
    expand_ranked_candidates(
        search_space,
        allowed_patterns,
        &[length],
        amount,
        &mut excluded,
    )
}

pub fn expand_ranked_candidates(
    search_space: &SearchSpace,
    allowed_patterns: &AllowedPatterns,
    lengths: &[usize],
    amount: usize,
    excluded: &mut HashSet<String>,
) -> Vec<String> {
    expand_ranked_candidates_with_provenance(
        search_space,
        allowed_patterns,
        lengths,
        amount,
        excluded,
    )
    .into_iter()
    .map(|candidate| candidate.password)
    .collect()
}

pub fn expand_candidates_with_provenance(
    search_space: &SearchSpace,
    allowed_patterns: &AllowedPatterns,
    length: usize,
    amount: usize,
) -> Vec<GeneratedCandidate> {
    let mut excluded = HashSet::new();
    expand_ranked_candidates_with_provenance(
        search_space,
        allowed_patterns,
        &[length],
        amount,
        &mut excluded,
    )
}

pub fn expand_ranked_candidates_with_provenance(
    search_space: &SearchSpace,
    allowed_patterns: &AllowedPatterns,
    lengths: &[usize],
    amount: usize,
    excluded: &mut HashSet<String>,
) -> Vec<GeneratedCandidate> {
    if amount == 0 {
        return Vec::new();
    }

    let tokens = combined_tokens(search_space);
    if tokens.is_empty() {
        return Vec::new();
    }

    let numbers = expansion_numbers(search_space);
    let symbols = expansion_symbols(search_space);
    let empty_values = vec![String::new()];
    let mut candidates = Vec::with_capacity(amount.min(1024));
    let fallback_token_arities = prioritized_token_arities(
        &tokens,
        &numbers,
        &symbols,
        lengths,
        allowed_patterns.max_token_slots(),
    );

    // The phase loop is intentionally outside the length loop. A fallback
    // candidate at a shorter length must never preempt a model pattern at a
    // later length.
    for (phase_index, patterns) in
        pattern_phases(search_space, allowed_patterns, &fallback_token_arities)
            .into_iter()
            .enumerate()
    {
        let source_phase = PATTERN_PHASE_NAMES[phase_index];
        for pattern in patterns {
            let token_slots = pattern_token_slots(&pattern);
            if token_slots.is_empty() {
                continue;
            }
            let number_values = if pattern.contains("{number}") || pattern.contains("{year}") {
                &numbers
            } else {
                &empty_values
            };
            let symbol_count = pattern.matches("{symbol}").count();
            let first_symbol_values = if symbol_count >= 1 {
                &symbols
            } else {
                &empty_values
            };
            let second_symbol_values = if symbol_count >= 2 {
                &symbols
            } else {
                &empty_values
            };

            // Numeric values are outside both requested lengths and token
            // combinations so every model-provided number is exhausted before
            // Rust's generic numeric fallback starts. Within each number,
            // model-preferred symbols likewise precede the Rust-owned symbol
            // alphabet.
            for number in number_values {
                for first_symbol in first_symbol_values {
                    for second_symbol in second_symbol_values {
                        for &length in lengths {
                            let mut token_indices = Vec::with_capacity(token_slots.len());
                            if append_token_assignments(
                                0,
                                &token_slots,
                                &tokens,
                                &mut token_indices,
                                &pattern,
                                number,
                                first_symbol,
                                second_symbol,
                                length,
                                excluded,
                                &mut candidates,
                                amount,
                                source_phase,
                            ) {
                                return candidates;
                            }
                        }
                    }
                }
            }
        }
    }

    candidates
}

#[allow(clippy::too_many_arguments)]
fn append_token_assignments(
    next_slot: usize,
    token_slots: &[usize],
    tokens: &[String],
    token_indices: &mut Vec<usize>,
    pattern: &str,
    number: &str,
    first_symbol: &str,
    second_symbol: &str,
    length: usize,
    excluded: &mut HashSet<String>,
    candidates: &mut Vec<GeneratedCandidate>,
    amount: usize,
    source_phase: &str,
) -> bool {
    if next_slot == token_slots.len() {
        let candidate = render_candidate_with_token_slots(
            pattern,
            token_slots,
            token_indices,
            tokens,
            number,
            first_symbol,
            second_symbol,
        );

        for (case_variant, variant) in case_variants(&candidate) {
            if variant.chars().count() == length && excluded.insert(variant.clone()) {
                candidates.push(GeneratedCandidate {
                    password: variant,
                    source_pattern: pattern.to_string(),
                    source_phase: source_phase.to_string(),
                    case_variant: case_variant.to_string(),
                });
                if candidates.len() == amount {
                    return true;
                }
            }
        }

        return false;
    }

    for token_index in 0..tokens.len() {
        token_indices.push(token_index);
        if append_token_assignments(
            next_slot + 1,
            token_slots,
            tokens,
            token_indices,
            pattern,
            number,
            first_symbol,
            second_symbol,
            length,
            excluded,
            candidates,
            amount,
            source_phase,
        ) {
            return true;
        }
        token_indices.pop();
    }

    false
}

fn pattern_token_slots(pattern: &str) -> Vec<usize> {
    let mut slots = BTreeSet::new();
    let mut remainder = pattern;

    while !remainder.is_empty() {
        let after_open = remainder
            .strip_prefix('{')
            .expect("validated patterns only contain placeholders");
        let end = after_open
            .find('}')
            .expect("validated patterns only contain complete placeholders");
        if let Some(slot) = token_slot_index(&after_open[..end]) {
            slots.insert(slot);
        }
        remainder = &after_open[end + 1..];
    }

    slots.into_iter().collect()
}

fn prioritized_token_arities(
    tokens: &[String],
    numbers: &[String],
    symbols: &[String],
    lengths: &[usize],
    max_token_slots: usize,
) -> Vec<usize> {
    let Some(max_requested_length) = lengths.iter().copied().max() else {
        return Vec::new();
    };
    let Some(shortest_token_length) = tokens.iter().map(|token| token.chars().count()).min() else {
        return Vec::new();
    };
    if shortest_token_length == 0 {
        return Vec::new();
    }

    // ASCII case variants preserve character counts, so this is a safe
    // exhaustive-pruning bound. Unicode case conversion can change a string's
    // character count; retain every configured arity in that case and use the
    // final variant-length check as the authority.
    let effective_max = if tokens.iter().all(|token| token.is_ascii()) {
        max_token_slots.min(max_requested_length / shortest_token_length)
    } else {
        max_token_slots
    };
    if effective_max == 0 {
        return Vec::new();
    }

    let mut extra_lengths = BTreeSet::from([0_usize]);
    let symbol_counts: &[usize] = if symbols.is_empty() { &[0] } else { &[0, 1, 2] };
    for number in numbers {
        let number_length = number.chars().count();
        for &symbol_count in symbol_counts {
            extra_lengths.insert(number_length + symbol_count);
        }
    }
    for &symbol_count in symbol_counts {
        extra_lengths.insert(symbol_count);
    }

    let token_lengths: Vec<usize> = tokens.iter().map(|token| token.chars().count()).collect();
    let mut reachable_sums = vec![false; max_requested_length + 1];
    reachable_sums[0] = true;
    let mut arities = Vec::with_capacity(effective_max);

    for arity in 1..=effective_max {
        let mut next_sums = vec![false; max_requested_length + 1];
        for (sum, reachable) in reachable_sums.iter().enumerate() {
            if !reachable {
                continue;
            }
            for token_length in &token_lengths {
                if let Some(next_sum) = sum.checked_add(*token_length)
                    && next_sum <= max_requested_length
                {
                    next_sums[next_sum] = true;
                }
            }
        }
        reachable_sums = next_sums;

        let earliest_length_rank = lengths
            .iter()
            .position(|target_length| {
                extra_lengths.iter().any(|extra_length| {
                    target_length
                        .checked_sub(*extra_length)
                        .is_some_and(|token_length| reachable_sums[token_length])
                })
            })
            .unwrap_or(usize::MAX);
        arities.push((earliest_length_rank, arity));
    }

    arities.sort_unstable();
    arities.into_iter().map(|(_, arity)| arity).collect()
}

fn expansion_symbols(search_space: &SearchSpace) -> Vec<String> {
    let mut symbols = Vec::new();
    for symbol in search_space
        .preferred_symbols
        .iter()
        .chain(rust_symbols().iter())
    {
        if symbol.chars().count() == 1
            && symbol
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_punctuation())
            && !symbols.contains(symbol)
        {
            symbols.push(symbol.clone());
        }
    }
    symbols
}

fn pattern_phases(
    search_space: &SearchSpace,
    allowed_patterns: &AllowedPatterns,
    fallback_token_arities: &[usize],
) -> [Vec<String>; 6] {
    let mut weighted_model_patterns: Vec<String> = search_space
        .likely_patterns
        .iter()
        .filter(|pattern| {
            is_valid_pattern_with_max_token_slots(pattern, allowed_patterns.max_token_slots())
                && search_space.pattern_weights.contains_key(*pattern)
        })
        .cloned()
        .collect();
    weighted_model_patterns.sort_by(|left, right| {
        search_space.pattern_weights[right].total_cmp(&search_space.pattern_weights[left])
    });

    let unweighted_model_patterns: Vec<String> = search_space
        .likely_patterns
        .iter()
        .filter(|pattern| {
            is_valid_pattern_with_max_token_slots(pattern, allowed_patterns.max_token_slots())
                && !search_space.pattern_weights.contains_key(*pattern)
        })
        .cloned()
        .collect();
    let model_patterns: HashSet<&str> = weighted_model_patterns
        .iter()
        .chain(unweighted_model_patterns.iter())
        .map(String::as_str)
        .collect();
    let configured_fallback_patterns: Vec<String> = allowed_patterns
        .explicit_patterns()
        .into_iter()
        .filter(|pattern| !model_patterns.contains(pattern.as_str()))
        .collect();

    let mut known_base_patterns: HashSet<String> = model_patterns
        .iter()
        .map(|pattern| (*pattern).to_string())
        .collect();
    known_base_patterns.extend(configured_fallback_patterns.iter().cloned());
    let generated_fallback_patterns: Vec<String> = allowed_patterns
        .generated_fallback_patterns_for_token_arities(fallback_token_arities)
        .into_iter()
        .filter(|pattern| known_base_patterns.insert(pattern.clone()))
        .collect();

    let mutation_sources: Vec<&str> = weighted_model_patterns
        .iter()
        .chain(unweighted_model_patterns.iter())
        .chain(configured_fallback_patterns.iter())
        .chain(generated_fallback_patterns.iter())
        .map(String::as_str)
        .collect();

    let mut one_symbol_mutations = Vec::new();
    let mut known_derived_patterns = HashSet::new();
    for source in &mutation_sources {
        for mutation in rust_derived_symbol_mutations(source) {
            if !model_patterns.contains(mutation.as_str())
                && known_derived_patterns.insert(mutation.clone())
            {
                one_symbol_mutations.push(mutation);
            }
        }
    }

    let mut two_symbol_mutations = Vec::new();
    for source in &mutation_sources {
        for mutation in rust_derived_two_symbol_mutations(source) {
            if !model_patterns.contains(mutation.as_str())
                && known_derived_patterns.insert(mutation.clone())
            {
                two_symbol_mutations.push(mutation);
            }
        }
    }

    [
        weighted_model_patterns,
        unweighted_model_patterns,
        configured_fallback_patterns,
        generated_fallback_patterns,
        one_symbol_mutations,
        two_symbol_mutations,
    ]
}

fn combined_tokens(search_space: &SearchSpace) -> Vec<String> {
    let mut tokens = Vec::new();
    for token in search_space
        .primary_tokens
        .iter()
        .chain(search_space.secondary_tokens.iter())
    {
        if !token.is_empty() && !tokens.contains(token) {
            tokens.push(token.clone());
        }
    }
    tokens
}

/// Keep model-supplied numeric values first, then add deterministic two-digit
/// fragments for each four-digit value and the compiled Rust numeric list.
/// String slices intentionally preserve a leading zero in a suffix such as
/// `2005 -> "05"`.
fn expansion_numbers(search_space: &SearchSpace) -> Vec<String> {
    let mut numbers = Vec::new();
    for value in &search_space.important_numbers {
        if !numbers.contains(value) {
            numbers.push(value.clone());
        }
    }

    for value in &search_space.important_numbers {
        let bytes = value.as_bytes();
        if bytes.len() == 4 && bytes.iter().all(u8::is_ascii_digit) {
            for fragment in [&value[..2], &value[2..]] {
                if !numbers.iter().any(|number| number == fragment) {
                    numbers.push(fragment.to_string());
                }
            }
        }
    }
    for value in rust_numbers() {
        if !numbers.contains(&value) {
            numbers.push(value);
        }
    }

    if numbers.is_empty() {
        vec![String::new()]
    } else {
        numbers
    }
}

fn render_candidate_with_token_slots(
    pattern: &str,
    token_slots: &[usize],
    token_indices: &[usize],
    tokens: &[String],
    number: &str,
    first_symbol: &str,
    second_symbol: &str,
) -> String {
    let mut candidate = String::with_capacity(
        pattern.len()
            + token_indices
                .iter()
                .map(|index| tokens[*index].len())
                .sum::<usize>()
            + number.len()
            + first_symbol.len()
            + second_symbol.len(),
    );
    let mut remainder = pattern;
    let mut symbol_occurrence = 0;

    while !remainder.is_empty() {
        let after_open = remainder
            .strip_prefix('{')
            .expect("validated patterns only contain placeholders");
        let end = after_open
            .find('}')
            .expect("validated patterns only contain complete placeholders");
        let placeholder = &after_open[..end];
        let value = match placeholder {
            "number" | "year" => number,
            "symbol" => {
                let symbol = match symbol_occurrence {
                    0 => first_symbol,
                    1 => second_symbol,
                    _ => unreachable!("validated patterns contain at most two symbol placeholders"),
                };
                symbol_occurrence += 1;
                symbol
            }
            _ => {
                let token_slot = token_slot_index(placeholder)
                    .expect("validated patterns only contain supported placeholders");
                let binding_index = token_slots
                    .binary_search(&token_slot)
                    .expect("every token slot has a selected token");
                tokens[token_indices[binding_index]].as_str()
            }
        };
        candidate.push_str(value);
        remainder = &after_open[end + 1..];
    }

    candidate
}

#[cfg(test)]
fn render_candidate(
    pattern: &str,
    first: &str,
    second: &str,
    number: &str,
    first_symbol: &str,
    second_symbol: &str,
) -> String {
    let token_slots = pattern_token_slots(pattern);
    let tokens = vec![first.to_string(), second.to_string()];
    let token_indices = token_slots
        .iter()
        .map(|slot| usize::from(*slot == 2))
        .collect::<Vec<_>>();

    render_candidate_with_token_slots(
        pattern,
        &token_slots,
        &token_indices,
        &tokens,
        number,
        first_symbol,
        second_symbol,
    )
}

fn case_variants(candidate: &str) -> Vec<(&'static str, String)> {
    let mut variants = vec![
        ("original", candidate.to_string()),
        ("lowercase", candidate.to_lowercase()),
        ("uppercase", candidate.to_uppercase()),
    ];
    let mut characters = candidate.chars();
    let capitalized = match characters.next() {
        Some(first) => format!(
            "{}{}",
            first.to_uppercase(),
            characters.as_str().to_lowercase()
        ),
        None => String::new(),
    };
    variants.push(("capitalized", capitalized));
    variants
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::{
        expand_candidates as expand_candidates_with_allowed_patterns,
        expand_ranked_candidates as expand_ranked_candidates_with_allowed_patterns,
        expand_ranked_candidates_with_provenance, expansion_numbers, expansion_symbols,
        pattern_phases, prioritized_token_arities, render_candidate,
    };
    use crate::search_space::{AllowedPatterns, SearchSpace};

    fn default_allowed_patterns() -> AllowedPatterns {
        AllowedPatterns::parse(
            include_str!("../config/allowed_patterns.txt"),
            "test allowed patterns",
        )
        .unwrap()
    }

    fn expand_candidates(search_space: &SearchSpace, length: usize, amount: usize) -> Vec<String> {
        let allowed_patterns = default_allowed_patterns();
        expand_candidates_with_allowed_patterns(search_space, &allowed_patterns, length, amount)
    }

    fn expand_ranked_candidates(
        search_space: &SearchSpace,
        lengths: &[usize],
        amount: usize,
        excluded: &mut HashSet<String>,
    ) -> Vec<String> {
        let allowed_patterns = default_allowed_patterns();
        expand_ranked_candidates_with_allowed_patterns(
            search_space,
            &allowed_patterns,
            lengths,
            amount,
            excluded,
        )
    }

    #[test]
    fn expands_patterns_and_deduplicates() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["54321".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token}{year}".to_string()],
            likely_lengths: vec![],
            pattern_weights: std::collections::HashMap::new(),
        };

        let candidates = expand_candidates(&search_space, 8, 10);
        assert!(candidates.contains(&"Dan54321".to_string()));
        assert!(candidates.contains(&"54321Dan".to_string()));
    }

    #[test]
    fn ranked_expansion_prioritizes_patterns_and_excludes_previous_batches() {
        let mut pattern_weights = HashMap::new();
        pattern_weights.insert("{token}{number}".to_string(), 0.9);
        pattern_weights.insert("{token}{year}".to_string(), 0.1);
        let search_space = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["99".to_string(), "1999".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token}{year}".to_string(), "{token}{number}".to_string()],
            likely_lengths: vec![5, 7],
            pattern_weights,
        };
        let mut excluded = HashSet::new();

        let first_batch = expand_ranked_candidates(&search_space, &[5, 7], 1, &mut excluded);
        let second_batch = expand_ranked_candidates(&search_space, &[5, 7], 10, &mut excluded);

        assert_eq!(first_batch, vec!["Dan99"]);
        assert!(!second_batch.contains(&"Dan99".to_string()));
        assert!(second_batch.contains(&"Dan1999".to_string()));
    }

    #[test]
    fn exhausts_all_model_patterns_before_shorter_fallback_candidates() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Ab".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token}{token}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let first_batch = expand_ranked_candidates(&search_space, &[2, 4], 4, &mut excluded);
        let second_batch = expand_ranked_candidates(&search_space, &[2, 4], 3, &mut excluded);

        assert_eq!(first_batch, vec!["AbAb", "abab", "ABAB", "Abab"]);
        assert_eq!(second_batch, vec!["Ab", "ab", "AB"]);
    }

    #[test]
    fn preserves_weighted_then_unweighted_then_fallback_then_symbol_mutation_phases() {
        let mut pattern_weights = HashMap::new();
        pattern_weights.insert("{token}{number}".to_string(), 0.2);
        pattern_weights.insert("{token}{year}".to_string(), 0.9);
        let search_space = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["99".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec![
                "{token1}{token2}".to_string(),
                "{token}{number}".to_string(),
                "{token}{year}".to_string(),
            ],
            likely_lengths: vec![],
            pattern_weights,
        };

        let [
            weighted,
            unweighted,
            configured_fallback,
            generated_fallback,
            one_symbol_mutations,
            two_symbol_mutations,
        ] = pattern_phases(&search_space, &default_allowed_patterns(), &[1, 2]);

        assert_eq!(weighted, vec!["{token}{year}", "{token}{number}"]);
        assert_eq!(unweighted, vec!["{token1}{token2}"]);
        assert!(configured_fallback.is_empty());
        assert!(!generated_fallback.contains(&"{token}{year}".to_string()));
        assert!(!generated_fallback.contains(&"{token}{number}".to_string()));
        assert!(!generated_fallback.contains(&"{token1}{token2}".to_string()));
        assert!(one_symbol_mutations.contains(&"{symbol}{token1}{token2}".to_string()));
        assert!(one_symbol_mutations.contains(&"{token1}{token2}{symbol}".to_string()));
        assert!(two_symbol_mutations.contains(&"{token1}{symbol}{token2}{symbol}".to_string()));
    }

    #[test]
    fn configured_fallback_patterns_keep_file_order_after_model_patterns() {
        let allowed_patterns = AllowedPatterns::parse(
            "{token}{number}\n{token}{year}\n{token}\n",
            "test allowed patterns",
        )
        .unwrap();
        let mut pattern_weights = HashMap::new();
        pattern_weights.insert("{token}{year}".to_string(), 1.0);
        let search_space = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["99".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token}{year}".to_string()],
            likely_lengths: vec![],
            pattern_weights,
        };

        let [weighted, _, fallback, _, _, _] =
            pattern_phases(&search_space, &allowed_patterns, &[1]);

        assert_eq!(weighted, vec!["{token}{year}"]);
        assert_eq!(fallback, vec!["{token}{number}", "{token}"]);
    }

    #[test]
    fn provenance_records_template_phase_and_case_variant() {
        let allowed_patterns =
            AllowedPatterns::parse("{token}\n", "test allowed patterns").unwrap();
        let mut pattern_weights = HashMap::new();
        pattern_weights.insert("{token}{number}".to_string(), 1.0);
        let search_space = SearchSpace {
            primary_tokens: vec!["dAN".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["99".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token}{number}".to_string()],
            likely_lengths: vec![],
            pattern_weights,
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates_with_provenance(
            &search_space,
            &allowed_patterns,
            &[5],
            4,
            &mut excluded,
        );

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.password.as_str())
                .collect::<Vec<_>>(),
            vec!["dAN99", "dan99", "DAN99", "Dan99"]
        );
        assert!(candidates.iter().all(|candidate| {
            candidate.source_pattern == "{token}{number}"
                && candidate.source_phase == "weighted_model"
        }));
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.case_variant.as_str())
                .collect::<Vec<_>>(),
            vec!["original", "lowercase", "uppercase", "capitalized"]
        );
    }

    #[test]
    fn provenance_distinguishes_fallback_and_symbol_mutation_phases() {
        let allowed_patterns =
            AllowedPatterns::parse("{token}\n", "test allowed patterns").unwrap();
        let search_space = SearchSpace {
            primary_tokens: vec!["Ab".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec!["!".to_string()],
            likely_patterns: vec![],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates_with_provenance(
            &search_space,
            &allowed_patterns,
            &[2, 3, 4],
            10_000,
            &mut excluded,
        );

        assert_eq!(
            candidates
                .iter()
                .find(|candidate| candidate.password == "Ab")
                .unwrap()
                .source_phase,
            "configured_fallback"
        );
        assert_eq!(
            candidates
                .iter()
                .find(|candidate| candidate.password == "Ab!")
                .unwrap()
                .source_phase,
            "rust_derived_one_symbol"
        );
        assert_eq!(
            candidates
                .iter()
                .find(|candidate| candidate.password == "Ab!!")
                .unwrap()
                .source_phase,
            "rust_derived_two_symbol"
        );
    }

    #[test]
    fn expands_all_tokens_for_two_token_patterns() {
        let mut pattern_weights = HashMap::new();
        pattern_weights.insert("{token}{number}".to_string(), 0.4);
        pattern_weights.insert("{token}{year}".to_string(), 0.3);
        pattern_weights.insert("{token1}{token2}{number}".to_string(), 0.3);
        let search_space = SearchSpace {
            primary_tokens: vec!["VR".to_string(), "Victor".to_string(), "Romeo".to_string()],
            secondary_tokens: vec!["NATO".to_string()],
            important_numbers: vec!["1999".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec![
                "{token}{number}".to_string(),
                "{token}{year}".to_string(),
                "{token1}{token2}{number}".to_string(),
            ],
            likely_lengths: vec![],
            pattern_weights,
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates(
            &search_space,
            &[8, 9, 10, 11, 12, 13, 14, 15, 16],
            1000,
            &mut excluded,
        );

        assert!(candidates.contains(&"VRVR1999".to_string()));
        assert!(candidates.contains(&"NATO1999".to_string()));
        assert!(candidates.len() > 9);

        let mut exact_length = HashSet::new();
        let length_twelve = expand_ranked_candidates(&search_space, &[12], 100, &mut exact_length);
        assert!(length_twelve.contains(&"VRVictor1999".to_string()));
        assert!(length_twelve.contains(&"VictorVR1999".to_string()));
    }

    #[test]
    fn expands_three_independent_token_slots_exhaustively() {
        let allowed_patterns =
            AllowedPatterns::parse("{token}\n", "test allowed patterns").unwrap();
        let search_space = SearchSpace {
            primary_tokens: vec!["0".to_string(), "1".to_string(), "2".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token1}{token2}{token3}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates_with_provenance(
            &search_space,
            &allowed_patterns,
            &[3],
            27,
            &mut excluded,
        );
        let passwords: Vec<&str> = candidates
            .iter()
            .map(|candidate| candidate.password.as_str())
            .collect();

        assert_eq!(passwords.len(), 27);
        assert!(passwords.contains(&"000"));
        assert!(passwords.contains(&"012"));
        assert!(passwords.contains(&"222"));
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.source_phase == "unweighted_model")
        );
    }

    #[test]
    fn repeated_token_indices_reuse_the_same_selected_value() {
        let allowed_patterns =
            AllowedPatterns::parse("{token}\n", "test allowed patterns").unwrap();
        let search_space = SearchSpace {
            primary_tokens: vec!["0".to_string(), "1".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token1}{token1}{token2}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates_with_provenance(
            &search_space,
            &allowed_patterns,
            &[3],
            4,
            &mut excluded,
        );
        let passwords: Vec<String> = candidates
            .into_iter()
            .map(|candidate| candidate.password)
            .collect();

        assert_eq!(passwords, vec!["000", "001", "110", "111"]);
    }

    #[test]
    fn generated_fallback_covers_three_token_combinations() {
        let allowed_patterns =
            AllowedPatterns::parse("{token_sequence}\n", "test allowed patterns").unwrap();
        let search_space = SearchSpace {
            primary_tokens: vec!["0".to_string(), "1".to_string(), "2".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec![],
            likely_patterns: vec![],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates_with_provenance(
            &search_space,
            &allowed_patterns,
            &[3],
            27,
            &mut excluded,
        );

        assert_eq!(candidates.len(), 27);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.source_phase == "generated_fallback")
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.password == "012")
        );
    }

    #[test]
    fn three_token_batches_match_the_single_exhaustive_prefix() {
        let allowed_patterns =
            AllowedPatterns::parse("{token}\n", "test allowed patterns").unwrap();
        let search_space = SearchSpace {
            primary_tokens: vec!["0".to_string(), "1".to_string(), "2".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token1}{token2}{token3}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut one_shot_excluded = HashSet::new();
        let one_shot = expand_ranked_candidates_with_provenance(
            &search_space,
            &allowed_patterns,
            &[3],
            27,
            &mut one_shot_excluded,
        );
        let mut batched_excluded = HashSet::new();
        let mut batched = Vec::new();

        while batched.len() < one_shot.len() {
            let remaining = one_shot.len() - batched.len();
            let batch = expand_ranked_candidates_with_provenance(
                &search_space,
                &allowed_patterns,
                &[3],
                remaining.min(5),
                &mut batched_excluded,
            );
            assert!(!batch.is_empty());
            batched.extend(batch);
        }

        assert_eq!(batched, one_shot);
    }

    #[test]
    fn length_aware_fallback_order_starts_at_the_first_feasible_arity() {
        let tokens = vec!["abcdef".to_string()];
        let numbers = vec!["1".to_string()];
        let symbols = vec!["!".to_string()];

        let arities = prioritized_token_arities(&tokens, &numbers, &symbols, &[25], 6);

        assert_eq!(arities.first(), Some(&4));
        assert_eq!(arities.len(), 4);
    }

    #[test]
    fn six_token_slots_make_a_six_component_candidate_reachable() {
        let allowed_patterns =
            AllowedPatterns::parse("{token}\n", "test allowed patterns").unwrap();
        let search_space = SearchSpace {
            primary_tokens: vec![
                "0".to_string(),
                "1".to_string(),
                "2".to_string(),
                "3".to_string(),
                "4".to_string(),
                "5".to_string(),
            ],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token1}{token2}{token3}{token4}{token5}{token6}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates_with_provenance(
            &search_space,
            &allowed_patterns,
            &[6],
            2_000,
            &mut excluded,
        );

        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.password == "012345")
        );
    }

    #[test]
    fn three_token_patterns_work_with_symbols_and_years() {
        let allowed_patterns =
            AllowedPatterns::parse("{token}\n", "test allowed patterns").unwrap();
        let search_space = SearchSpace {
            primary_tokens: vec!["A".to_string(), "B".to_string(), "C".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["99".to_string()],
            preferred_symbols: vec!["@".to_string()],
            likely_patterns: vec!["{token1}{symbol}{token2}{year}{token3}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates_with_provenance(
            &search_space,
            &allowed_patterns,
            &[6],
            1_000,
            &mut excluded,
        );

        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.password == "A@B99C")
        );
    }

    #[test]
    fn expands_two_tokens_number_and_symbol() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Victor".to_string()],
            secondary_tokens: vec!["Romeo".to_string()],
            important_numbers: vec!["99".to_string()],
            preferred_symbols: vec!["!".to_string()],
            likely_patterns: vec!["{token1}{token2}{number}{symbol}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates(&search_space, &[14], 100, &mut excluded);

        assert!(candidates.contains(&"VictorRomeo99!".to_string()));
        assert!(candidates.iter().all(|candidate| candidate.len() == 14));
    }

    #[test]
    fn rust_derived_mutations_cover_every_symbol_position() {
        let search_space = SearchSpace {
            primary_tokens: vec!["A".to_string(), "B".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["1".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token1}{token2}{number}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates(&search_space, &[4], 10_000, &mut excluded);

        assert!(candidates.contains(&"!AB1".to_string()));
        assert!(candidates.contains(&"A!B1".to_string()));
        assert!(candidates.contains(&"AB!1".to_string()));
        assert!(candidates.contains(&"AB1!".to_string()));
        assert_eq!(candidates.len(), excluded.len());
    }

    #[test]
    fn fallback_uses_every_ordered_pair_from_all_model_token_lists() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Al".to_string()],
            secondary_tokens: vec!["Bo".to_string()],
            important_numbers: vec!["7".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec![],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates(&search_space, &[5], 10_000, &mut excluded);

        assert!(candidates.contains(&"AlBo7".to_string()));
        assert!(candidates.contains(&"BoAl7".to_string()));
    }

    #[test]
    fn derives_two_digit_year_fragments_after_model_numbers() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["1999".to_string(), "2005".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec![],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };

        let numbers = expansion_numbers(&search_space);

        assert_eq!(&numbers[..6], ["1999", "2005", "19", "99", "20", "05"]);
        assert!(numbers[6..].contains(&"123".to_string()));
    }

    #[test]
    fn appends_generic_numbers_after_model_numbers_and_year_fragments() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Dan".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec!["2024".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec![],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };

        let numbers = expansion_numbers(&search_space);

        assert_eq!(&numbers[..3], ["2024", "20", "24"]);
        assert!(numbers[3..].contains(&"123".to_string()));
    }

    #[test]
    fn expands_two_symbol_slots_independently_with_rust_generic_numbers() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Rajesh".to_string()],
            secondary_tokens: vec!["Grower".to_string()],
            important_numbers: vec![],
            preferred_symbols: vec![".".to_string(), "@".to_string()],
            likely_patterns: vec!["{token1}{symbol}{token2}{symbol}{number}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates(&search_space, &[17], 10_000, &mut excluded);

        assert!(candidates.contains(&"Rajesh.Grower@123".to_string()));
        assert!(candidates.contains(&"Rajesh@Grower.123".to_string()));
        assert!(candidates.contains(&"Rajesh.Grower.123".to_string()));
    }

    #[test]
    fn rust_fallback_makes_the_rajesh_target_reachable_when_the_model_omits_numbers_and_symbols() {
        let mut pattern_weights = HashMap::new();
        pattern_weights.insert("{token}{token}".to_string(), 1.0);
        let search_space = SearchSpace {
            primary_tokens: vec!["Rajesh".to_string(), "Grower".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token}{token}".to_string()],
            likely_lengths: vec![8, 12],
            pattern_weights,
        };
        let [
            weighted,
            _,
            _,
            fallback,
            one_symbol_mutations,
            two_symbol_mutations,
        ] = pattern_phases(&search_space, &default_allowed_patterns(), &[1, 2]);
        let numbers = expansion_numbers(&search_space);
        let symbols = expansion_symbols(&search_space);

        assert_eq!(weighted, vec!["{token}{token}"]);
        assert!(fallback.contains(&"{token1}{token2}{number}".to_string()));
        assert!(
            !one_symbol_mutations.contains(&"{token1}{symbol}{token2}{symbol}{number}".to_string())
        );
        assert!(
            two_symbol_mutations.contains(&"{token1}{symbol}{token2}{symbol}{number}".to_string())
        );
        assert!(numbers.contains(&"123".to_string()));
        assert!(symbols.contains(&".".to_string()));
        assert!(symbols.contains(&"@".to_string()));
        assert_eq!(
            render_candidate(
                "{token1}{symbol}{token2}{symbol}{number}",
                "Rajesh",
                "Grower",
                "123",
                ".",
                "@",
            ),
            "Rajesh.Grower@123"
        );
    }

    #[test]
    fn derived_year_suffix_reaches_the_two_digit_year_symbol_candidate() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Victor".to_string()],
            secondary_tokens: vec!["Romeo".to_string()],
            important_numbers: vec!["1999".to_string()],
            preferred_symbols: vec![],
            likely_patterns: vec!["{token1}{token2}{year}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();
        let candidates = expand_ranked_candidates(&search_space, &[14], 100_000, &mut excluded);

        assert!(candidates.contains(&"VictorRomeo99!".to_string()));
    }

    #[test]
    fn finite_batches_follow_the_same_unique_stream_as_an_exhaustive_run() {
        let mut pattern_weights = HashMap::new();
        pattern_weights.insert("{token}{symbol}{symbol}".to_string(), 0.9);
        let search_space = SearchSpace {
            primary_tokens: vec!["Ab".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec!["@".to_string()],
            likely_patterns: vec!["{token}{symbol}{symbol}".to_string()],
            likely_lengths: vec![],
            pattern_weights,
        };
        let lengths = [4];
        let mut one_shot_excluded = HashSet::new();
        let one_shot =
            expand_ranked_candidates(&search_space, &lengths, 10_000, &mut one_shot_excluded);
        let mut batch_excluded = HashSet::new();
        let mut batched = Vec::new();

        loop {
            let batch = expand_ranked_candidates(&search_space, &lengths, 128, &mut batch_excluded);
            if batch.is_empty() {
                break;
            }
            batched.extend(batch);
        }

        assert_eq!(batched, one_shot);
        assert!(batched.len() > 128);
        assert_eq!(batched.len(), batch_excluded.len());
    }

    #[test]
    fn model_symbols_are_tried_before_rust_symbols() {
        let search_space = SearchSpace {
            primary_tokens: vec!["Ab".to_string()],
            secondary_tokens: vec![],
            important_numbers: vec![],
            preferred_symbols: vec!["@".to_string()],
            likely_patterns: vec!["{token}{symbol}".to_string()],
            likely_lengths: vec![],
            pattern_weights: HashMap::new(),
        };
        let mut excluded = HashSet::new();

        let candidates = expand_ranked_candidates(&search_space, &[3], 4, &mut excluded);

        assert_eq!(candidates, vec!["Ab@", "ab@", "AB@", "Ab!"]);
    }
}
