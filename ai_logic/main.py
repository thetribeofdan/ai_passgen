import argparse
import json
from generator import generate_search_space


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Persona reasoning search-space generator"
    )

    parser.add_argument(
        "--input", required=True, help="Path to persona input file"
    )
    parser.add_argument(
        "--length", type=int, default=10, help="Retained for CLI compatibility"
    )
    parser.add_argument(
        "--amount", type=int, default=20, help="Retained for CLI compatibility"
    )

    # NEW OPTIONAL ARGUMENTS
    parser.add_argument(
        "--algo",
        default=None,
        help="Hash algorithm for cracking (optional)",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Number of CPU threads for cracking (optional)",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    # Load persona
    with open(args.input, "r") as f:
        persona = json.load(f)

    print(
        json.dumps(generate_search_space(persona), separators=(",", ":")),
        flush=True,
    )


if __name__ == "__main__":
    main()
