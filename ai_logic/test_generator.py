import unittest

from generator import is_valid_pattern_with_max_token_slots, validate_search_space


class IndexedTokenPatternTests(unittest.TestCase):
    def test_accepts_indexed_token_slots_within_the_selected_bound(self) -> None:
        self.assertTrue(
            is_valid_pattern_with_max_token_slots(
                "{token1}{symbol}{token2}{year}{token3}",
                3,
            )
        )
        self.assertTrue(
            is_valid_pattern_with_max_token_slots(
                "{token1}{token2}{token3}{token4}{token5}{token6}{number}{symbol}{symbol}",
                6,
            )
        )

    def test_rejects_invalid_or_out_of_range_token_indices(self) -> None:
        self.assertFalse(is_valid_pattern_with_max_token_slots("{token0}", 6))
        self.assertFalse(is_valid_pattern_with_max_token_slots("{token01}", 6))
        self.assertFalse(is_valid_pattern_with_max_token_slots("{token7}", 6))

    def test_validation_preserves_a_valid_three_token_model_pattern(self) -> None:
        search_space = validate_search_space(
            {
                "primary_tokens": ["A", "B", "C"],
                "secondary_tokens": [],
                "important_numbers": [],
                "preferred_symbols": [],
                "likely_patterns": ["{token1}{token2}{token3}"],
                "likely_lengths": [4],
                "pattern_weights": {"{token1}{token2}{token3}": 0.8},
            },
            3,
        )

        self.assertEqual(
            search_space["likely_patterns"],
            ["{token1}{token2}{token3}"],
        )
        self.assertEqual(
            search_space["pattern_weights"],
            {"{token1}{token2}{token3}": 0.8},
        )


if __name__ == "__main__":
    unittest.main()
