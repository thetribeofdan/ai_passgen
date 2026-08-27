import argparse
import json
import sys
from pathlib import Path
from typing import Any

from generator import generate_search_space


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
    value: dict[str, Any],
) -> None:
    """
    Write exactly one JSON object to stdout.

    Rust consumes stdout as the machine-readable interface,
    so diagnostics must never be written here.
    """

    sys.stdout.write(
        json.dumps(
            value,
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

    args = parser.parse_args()

    try:
        persona = load_persona(
            args.input
        )

        search_space = generate_search_space(
            persona
        )

        write_json_stdout(
            search_space
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
