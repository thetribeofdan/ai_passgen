use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::search_space::SearchSpace;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrackedPasswordPattern {
    pub source_pattern: String,
    pub source_phase: String,
    pub case_variant: String,
}

#[derive(Debug, Serialize)]
pub struct CrackRunRecord {
    pub run_id: String,
    pub condition: String,
    pub persona_id: String,
    pub hash_algorithm: String,
    pub target_hash: String,
    pub persona_json: Value,
    pub llm_model_id: String,
    pub llm_raw_output: String,
    pub validated_search_space: SearchSpace,
    pub search_space_size: usize,
    pub cracked: bool,
    pub rank: Option<usize>,
    pub cracked_password_pattern: Option<CrackedPasswordPattern>,
    pub time_to_first_match_seconds: Option<f64>,
    pub total_runtime_seconds: f64,
    pub generation_time_seconds: f64,
    pub verification_time_seconds: f64,
    pub threads_utilization: f64,
    pub candidate_throughput: f64,
    pub generation_throughput: f64,
    pub observed_password_length: Option<usize>,
    pub observed_pattern: Option<String>,
}

impl CrackRunRecord {
    pub fn write_json(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        fs::write(path, format!("{json}\n"))
    }
}

pub fn seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

pub fn throughput(count: usize, duration: Duration) -> f64 {
    let seconds = duration.as_secs_f64();
    if seconds > 0.0 {
        count as f64 / seconds
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{CrackRunRecord, CrackedPasswordPattern};
    use crate::search_space::SearchSpace;

    #[test]
    fn serializes_the_self_contained_research_record_shape() {
        let mut record = CrackRunRecord {
            run_id: "run-test".to_string(),
            condition: "ranked_search".to_string(),
            persona_id: "persona-test".to_string(),
            hash_algorithm: "sha256".to_string(),
            target_hash: "hash".to_string(),
            persona_json: json!({"persona": {"name": "Dan"}}),
            llm_model_id: "test-model".to_string(),
            llm_raw_output: "{\"primary_tokens\":[\"Dan\"]}".to_string(),
            validated_search_space: SearchSpace {
                primary_tokens: vec!["Dan".to_string()],
                secondary_tokens: vec![],
                important_numbers: vec!["1".to_string()],
                preferred_symbols: vec![],
                likely_patterns: vec!["{token}{number}".to_string()],
                likely_lengths: vec![4],
                pattern_weights: Default::default(),
            },
            search_space_size: 10,
            cracked: true,
            rank: Some(1),
            cracked_password_pattern: Some(CrackedPasswordPattern {
                source_pattern: "{token}".to_string(),
                source_phase: "weighted_model".to_string(),
                case_variant: "original".to_string(),
            }),
            time_to_first_match_seconds: Some(1.0),
            total_runtime_seconds: 1.0,
            generation_time_seconds: 0.5,
            verification_time_seconds: 0.5,
            threads_utilization: 1.0,
            candidate_throughput: 20.0,
            generation_throughput: 20.0,
            observed_password_length: None,
            observed_pattern: None,
        };

        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["search_space_size"], 10);
        assert_eq!(json["cracked"], true);
        assert_eq!(json["rank"], 1);
        assert_eq!(json["persona_json"]["persona"]["name"], "Dan");
        assert_eq!(json["llm_model_id"], "test-model");
        assert_eq!(json["llm_raw_output"], "{\"primary_tokens\":[\"Dan\"]}");
        assert_eq!(json["validated_search_space"]["primary_tokens"][0], "Dan");
        assert_eq!(
            json["cracked_password_pattern"]["source_pattern"],
            "{token}"
        );
        assert_eq!(
            json["cracked_password_pattern"]["source_phase"],
            "weighted_model"
        );
        assert_eq!(json["cracked_password_pattern"]["case_variant"], "original");

        record.cracked = false;
        record.rank = None;
        record.cracked_password_pattern = None;
        record.time_to_first_match_seconds = None;
        let exhausted_json = serde_json::to_value(record).unwrap();
        assert!(exhausted_json["rank"].is_null());
        assert!(exhausted_json["cracked_password_pattern"].is_null());
        assert!(exhausted_json["time_to_first_match_seconds"].is_null());
    }
}
