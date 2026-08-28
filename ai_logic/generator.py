import json
import os
import re
import string
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=True)


DEFAULT_MODEL = "openai/gpt-oss-20b"

SEARCH_SPACE_FIELDS = (
    "primary_tokens",
    "secondary_tokens",
    "important_numbers",
    "preferred_symbols",
    "likely_patterns",
    "likely_lengths",
    "pattern_weights",
)


ALLOWED_PLACEHOLDERS = {
    "token",
    "token1",
    "token2",
    "number",
    "year",
    "symbol",
}

MAX_TOKEN_PLACEHOLDERS = 2
MAX_NUMERIC_PLACEHOLDERS = 1
MAX_SYMBOL_PLACEHOLDERS = 2
MAX_PATTERN_PLACEHOLDERS = 5


SYSTEM_PROMPT = """
You are the semantic reasoning component of AI-PassGen.

Your task is to analyse a fictional synthetic persona and infer a
compact password search-space specification.

Do NOT generate passwords.

Do NOT provide explanations, reasoning, markdown, or code.

Return exactly one JSON object with these seven fields:

{
  "primary_tokens": [],
  "secondary_tokens": [],
  "important_numbers": [],
  "preferred_symbols": [],
    "likely_patterns": [],
    "likely_lengths": [],
    "pattern_weights": {}
}

Rules:

1. Every field must contain an array of strings.
2. Include only concepts reasonably supported by the supplied persona.
3. Do not invent unsupported personal information.
4. Do not output complete password candidates.
5. Valid pattern variables are:
   {token}
   {token1}
   {token2}
   {number}
   {year}
   {symbol}
6. Keep the search space compact and relevant.
7. Use an empty array when a category has no relevant values.
8. For broad categories such as NATO phonetic alphabet, include only the
concepts directly supported by the persona.
9. Patterns are ranking hints only: Rust will deterministically enumerate its
own fallback templates and one- and two-symbol mutations after every model
pattern.
10. A pattern must contain one or two token placeholders, at most one of
{number}/{year}, at most two {symbol} placeholders, and no literal text.
When {symbol} appears twice, each occurrence is an independently selected
symbol value.
""".strip()


def create_client() -> OpenAI:
    """
    Create the OpenAI-compatible client for the dedicated
    Hugging Face Inference Endpoint.
    """

    endpoint_url = os.getenv("HF_INFERENCE_URL")
    token = os.getenv("HF_TOKEN")

    if not endpoint_url:
        raise RuntimeError(
            "HF_INFERENCE_URL is not configured."
        )

    if not token:
        raise RuntimeError(
            "HF_TOKEN is not configured."
        )

    endpoint_url = endpoint_url.rstrip("/")

    if not endpoint_url.endswith("/v1"):
        endpoint_url = f"{endpoint_url}/v1"

    return OpenAI(
        base_url=f"{endpoint_url}/",
        api_key=token,
    )


def build_prompt(
    persona: dict[str, Any],
) -> str:
    """
    Build a deterministic prompt from a synthetic persona.
    """

    persona_json = json.dumps(
        persona,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )

    return (
        "Analyse this fictional synthetic persona and infer "
        "the compact AI-PassGen search space.\n\n"
        f"Persona:\n{persona_json}"
    )


def configured_model_id() -> str:
    """Return the model identifier recorded with each research run."""

    return os.getenv(
        "HF_MODEL_ID",
        DEFAULT_MODEL,
    )


def generate_search_space_with_model_output(
    persona: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    """
    Query the dedicated Hugging Face endpoint and return the validated
    SearchSpace, raw model response, and configured model identifier.
    """

    raw_response, model_id = request_huggingface(
        persona
    )

    parsed = extract_json(
        raw_response
    )

    if parsed is None:
        raise ValueError(
            "The model response did not contain a valid "
            "SearchSpace JSON object."
        )

    return (
        validate_search_space(
            parsed
        ),
        raw_response,
        model_id,
    )


def generate_search_space(
    persona: dict[str, Any],
) -> dict[str, Any]:
    """Return only the validated SearchSpace for callers that do not log runs."""

    search_space, _, _ = generate_search_space_with_model_output(
        persona
    )

    return search_space


def request_huggingface(
    persona: dict[str, Any],
) -> tuple[str, str]:
    """
    Send the persona to the GPT-OSS endpoint.

    Structured JSON is requested through the OpenAI-compatible
    response_format interface exposed by the endpoint.
    """

    client = create_client()

    model = configured_model_id()

    prompt = build_prompt(
        persona
    )

    completion = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        temperature=0.0,
        max_tokens=4096,
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "ai_passgen_search_space",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "primary_tokens": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                        },
                        "secondary_tokens": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                        },
                        "important_numbers": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                        },
                        "preferred_symbols": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                        },
                        "likely_patterns": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                        },
                        "likely_lengths": {
                            "type": "array",
                            "items": {"type": "integer"},
                        },
                        "pattern_weights": {
                            "type": "object",
                            "additionalProperties": {"type": "number"},
                        },
                    },
                    "required": [
                        "primary_tokens",
                        "secondary_tokens",
                        "important_numbers",
                        "preferred_symbols",
                        "likely_patterns",
                        "likely_lengths",
                        "pattern_weights",
                    ],
                    "additionalProperties": False,
                },
            },
        },
    )

    if not completion.choices:
        raise RuntimeError(
            "Hugging Face endpoint returned no choices."
        )

    content = (
        completion
        .choices[0]
        .message
        .content
    )

    if not isinstance(content, str):
        raise RuntimeError(
            "Hugging Face endpoint returned no text content."
        )

    return content, model


def extract_json(
    text: str,
) -> dict[str, Any] | None:
    """
    Extract a SearchSpace JSON object from the model response.

    This supports harmless wrappers such as:

        final{...}

    while still requiring an actual JSON object.
    """

    if not isinstance(text, str):
        return None

    decoder = json.JSONDecoder()

    for match in re.finditer(
        r"\{",
        text,
    ):
        try:
            value, _ = decoder.raw_decode(
                text[match.start():]
            )
        except json.JSONDecodeError:
            continue

        if not isinstance(value, dict):
            continue

        if all(
            field in value
            for field in SEARCH_SPACE_FIELDS
        ):
            return value

    return None


def validate_search_space(
    value: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate and normalize a SearchSpace returned by the model.
    """

    if not isinstance(value, dict):
        raise ValueError(
            "SearchSpace must be a JSON object."
        )

    result: dict[str, Any] = {}

    for field in SEARCH_SPACE_FIELDS[:5]:
        field_value = value.get(field)
        if not isinstance(field_value, list):
            raise ValueError(f"{field} must be an array.")
        if not all(isinstance(item, str) for item in field_value):
            raise ValueError(f"{field} must contain only strings.")
        result[field] = list(dict.fromkeys(
            item.strip() for item in field_value if item.strip()
        ))

    if not result["primary_tokens"] and not result["secondary_tokens"]:
        raise ValueError(
            "SearchSpace contains no usable token values."
        )

    result["preferred_symbols"] = [
        symbol
        for symbol in result["preferred_symbols"]
        if len(symbol) == 1 and symbol in string.punctuation
    ]

    result["likely_patterns"] = [
        pattern
        for pattern in result["likely_patterns"]
        if is_valid_pattern(pattern)
    ]

    lengths = value.get("likely_lengths", [])
    if not isinstance(lengths, list) or not all(
        isinstance(length, int) and 4 <= length <= 32 for length in lengths
    ):
        raise ValueError("likely_lengths must contain integers from 4 to 32.")
    result["likely_lengths"] = list(dict.fromkeys(lengths))

    weights = value.get("pattern_weights", {})
    if not isinstance(weights, dict):
        raise ValueError("pattern_weights must be an object.")
    result["pattern_weights"] = {
        pattern: weight
        for pattern, weight in weights.items()
        if pattern in result["likely_patterns"]
        and isinstance(weight, (int, float))
        and 0 <= weight <= 1
    }

    return result


def is_valid_pattern(pattern: str) -> bool:
    """Validate the bounded placeholder grammar owned by Rust."""
    if not isinstance(pattern, str) or "{" not in pattern:
        return False
    placeholders = re.findall(r"\{([^{}]+)\}", pattern)
    if (
        not placeholders
        or "".join(f"{{{placeholder}}}" for placeholder in placeholders)
        != pattern
        or any(
            placeholder not in ALLOWED_PLACEHOLDERS
            for placeholder in placeholders
        )
    ):
        return False
    token_count = sum(
        placeholder.startswith("token")
        for placeholder in placeholders
    )
    numeric_count = sum(
        placeholder in {"number", "year"}
        for placeholder in placeholders
    )
    symbol_count = placeholders.count("symbol")
    return (
        1 <= token_count <= MAX_TOKEN_PLACEHOLDERS
        and numeric_count <= MAX_NUMERIC_PLACEHOLDERS
        and symbol_count <= MAX_SYMBOL_PLACEHOLDERS
        and len(placeholders) <= MAX_PATTERN_PLACEHOLDERS
    )
