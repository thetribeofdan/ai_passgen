import argparse
import json
import sys
from pathlib import Path
from typing import Any

from generator import (
    DEFAULT_MAX_TOKEN_SLOTS,
    MAX_TOKEN_SLOTS,
    generate_search_space_with_model_output,
)


def load_persona(
    input_path: str,
) -> dict[str, Any]:
    """
    Load a synthetic persona from a JSON file.
    """

    path = Path(input_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Persona file not found: {path}"
        )

    try:
        value = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in persona file: {path}"
        ) from exc

    if not isinstance(value, dict):
        raise ValueError(
            "Persona input must be a JSON object."
        )

    return value


def write_json_stdout(
    persona_json: dict[str, Any],
    search_space: dict[str, Any],
    llm_raw_output: str,
    llm_model_id: str,
) -> None:
    """
    Write exactly one model-generation record to stdout.

    Rust consumes stdout as the machine-readable interface,
    so diagnostics must never be written here.
    """

    sys.stdout.write(
        json.dumps(
            {
                "persona_json": persona_json,
                "search_space": search_space,
                "llm_raw_output": llm_raw_output,
                "llm_model_id": llm_model_id,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )

    sys.stdout.write("\n")
    sys.stdout.flush()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate an AI-PassGen SearchSpace from "
            "a synthetic persona."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the persona JSON file.",
    )

    parser.add_argument(
        "--max-token-slots",
        type=int,
        default=DEFAULT_MAX_TOKEN_SLOTS,
        help=(
            "Maximum indexed token slots allowed in a pattern "
            f"(1-{MAX_TOKEN_SLOTS}; default: "
            f"{DEFAULT_MAX_TOKEN_SLOTS})."
        ),
    )

    args = parser.parse_args()

    if not 1 <= args.max_token_slots <= MAX_TOKEN_SLOTS:
        parser.error(
            f"--max-token-slots must be between 1 and {MAX_TOKEN_SLOTS}."
        )

    try:
        persona = load_persona(
            args.input
        )

        search_space, llm_raw_output, llm_model_id = generate_search_space_with_model_output(
            persona,
            args.max_token_slots,
        )

        write_json_stdout(
            persona,
            search_space,
            llm_raw_output,
            llm_model_id,
        )

        return 0

    except Exception as exc:
        # IMPORTANT:
        # Errors go to stderr, never stdout.
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
