import argparse
import json
import os
from dotenv import load_dotenv
from generator import generate_passwords  # <-- new import

load_dotenv()

try:
    from openai import OpenAI
    openai = OpenAI()
except ImportError:
    openai = None


def parse_arguments():
    parser = argparse.ArgumentParser(description="AI-based password generator")

    parser.add_argument("--input", required=True, help="Path to persona input file")
    # parser.add_argument("--output", required=True, help="Path to output password file")
    parser.add_argument("--length", type=int, default=10, help="Password length")
    parser.add_argument("--amount", type=int, default=20, help="Number of passwords")

    # NEW OPTIONAL ARGUMENTS
    parser.add_argument("--algo", default=None, help="Hash algorithm for cracking (optional): sha256, sha512, md5, bcrypt, argon2")

    parser.add_argument("--threads", type=int, default=None, help="Number of CPU threads for cracking (optional)")

    return parser.parse_args()


def main():
    args = parse_arguments()

    # Load persona
    with open(args.input, "r") as f:
        persona = json.load(f)

    # Generate passwords using AI or fallback
    passwords = generate_passwords(persona, args.length, args.amount)

    for p in passwords:
        print(p, flush=True)


if __name__ == "__main__":
    main()
