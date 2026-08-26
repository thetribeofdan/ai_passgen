import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_MODEL = "DanTheBadGuy/ai-passgen-gpt-oss-20b-lora-v2"
DEFAULT_PATTERNS = [
    "{token}{year}",
    "{token}{number}",
    "{token}{symbol}{number}",
    "{token1}{token2}{number}",
]


def generate_search_space(persona: dict) -> dict:
    """Ask the model for concepts, then use a safe offline fallback."""
    response = request_huggingface(build_prompt(persona))
    if response is not None:
        try:
            return validate_search_space(response)
        except ValueError:
            pass
    return fallback_search_space(persona)


def build_prompt(persona: dict) -> str:
    persona_json = json.dumps(persona, ensure_ascii=True, sort_keys=True)
    return (
        "You are a cybersecurity research model. Infer likely concepts from "
        "this fictional persona, but never generate passwords. Return only a "
        "JSON object with arrays named primary_tokens, secondary_tokens, "
        "important_numbers, preferred_symbols, and likely_patterns. Use only "
        "{token}, {token1}, {token2}, {number}, {year}, and {symbol}. "
        "Keep unsupported details out of the result. Persona: "
        f"{persona_json}"
    )


def request_huggingface(prompt: str) -> dict | None:
    model_url = os.getenv("HF_INFERENCE_URL")
    if not model_url:
        model_id = os.getenv("HF_MODEL_ID", DEFAULT_MODEL)
        model_url = f"https://api-inference.huggingface.co/models/{model_id}"

    token = os.getenv("HF_TOKEN")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(
        model_url,
        data=json.dumps(
            {"inputs": prompt, "parameters": {"max_new_tokens": 512}}
        ).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=60) as result:
            payload = json.loads(result.read().decode())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return None

    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        generated = payload[0].get("generated_text")
        return extract_json(generated) if isinstance(generated, str) else None
    if isinstance(payload, dict):
        generated = payload.get("generated_text") or payload.get("text")
        return (
            extract_json(generated) if isinstance(generated, str) else payload
        )
    return None


def extract_json(text: str) -> dict | None:
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text):
        try:
            value, _ = decoder.raw_decode(text[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "primary_tokens" in value:
            return value
    return None


def validate_search_space(value: dict) -> dict:
    fields = [
        "primary_tokens",
        "secondary_tokens",
        "important_numbers",
        "preferred_symbols",
        "likely_patterns",
    ]
    result = {field: value.get(field, []) for field in fields}
    for field in fields:
        if not isinstance(result[field], list) or not all(
            isinstance(item, str) for item in result[field]
        ):
            raise ValueError(f"{field} must be an array of strings")
    if not result["primary_tokens"] and not result["secondary_tokens"]:
        raise ValueError("model returned no tokens")
    result["preferred_symbols"] = [
        symbol for symbol in result["preferred_symbols"] if len(symbol) == 1
    ]
    result["likely_patterns"] = [
        pattern
        for pattern in result["likely_patterns"]
        if pattern in DEFAULT_PATTERNS
    ]
    result["likely_patterns"] = result["likely_patterns"] or DEFAULT_PATTERNS
    return result


def fallback_search_space(persona: dict) -> dict:
    primary = []
    secondary = []
    numbers = []
    for key in ("name", "username", "pet_name"):
        value = persona.get(key)
        if isinstance(value, str) and value.strip():
            primary.append(value.strip().replace(" ", ""))
    for key in (
        "hobbies",
        "favourite_color",
        "favorite_color",
        "birthplace",
        "favourite_movies",
        "favorite_movies",
    ):
        value = persona.get(key)
        values = value if isinstance(value, list) else [value]
        secondary.extend(str(item).replace(" ", "") for item in values if item)
    for key in ("dob", "graduation_year"):
        value = persona.get(key)
        if value:
            numbers.append(str(value)[-4:])
    return validate_search_space({
        "primary_tokens": primary or ["user"],
        "secondary_tokens": secondary,
        "important_numbers": numbers,
        "preferred_symbols": ["!", "@", "#"],
        "likely_patterns": DEFAULT_PATTERNS,
    })
