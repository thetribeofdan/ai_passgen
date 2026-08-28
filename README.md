# AI-PassGen

### AI-Assisted Password Generation and Hash Cracking Research Tool

AI-PassGen is a **research-oriented password analysis tool** designed to explore how **AI-generated, persona-based password dictionaries** can improve password cracking strategies.

The tool combines:

- AI-driven password generation
- OSINT-style persona input
- multithreaded hash cracking
- adaptive infinite cracking mode

Unlike traditional brute force tools, AI-PassGen generates **context-aware passwords derived from user traits**, simulating how attackers might construct targeted password dictionaries.

This project is part of a **cybersecurity research study investigating intelligent password generation strategies**.

---

# Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Modes of Operation](#modes-of-operation)
- [Command Line Options](#command-line-options)
- [Examples](#examples)
- [Supported Hash Algorithms](#supported-hash-algorithms)
- [Performance](#performance)
- [Project Structure](#project-structure)
- [Security & Ethical Use](#security--ethical-use)
- [License](#license)

---

# Overview

Traditional password cracking tools rely on:

- brute force
- wordlists
- rule-based mutations

AI-PassGen introduces a **new approach**:

Instead of blindly guessing passwords, it **uses AI to generate passwords based on user personas** such as:

- names
- hobbies
- favorite teams
- pets
- locations
- interests
- personal dates

This mimics how **real attackers build targeted password dictionaries during OSINT-based attacks**.

The generated passwords are then tested against a provided hash using a **high-performance Rust cracking engine**.

---

# Features

### AI Password Generation

Generates passwords derived from persona attributes using an LLM.

Examples of persona attributes:

- Name
- Pet name
- Favorite movie
- Favorite sport
- Hometown
- Graduation year
- Hobbies

The AI combines these into **memorable yet realistic password candidates**.

---

### Multithreaded Cracking Engine

The cracking engine is written in **Rust** and uses:

- CPU parallelism
- thread pools
- efficient hashing

All CPU cores are used by default.

You can optionally limit threads with:

--threads N

---

### Automatic Hash Detection

If no algorithm is provided, the system automatically attempts to detect the hash type.

Examples:

| Hash Prefix    | Detected Algorithm |
| -------------- | ------------------ |
| `$2a$`, `$2b$` | bcrypt             |
| `$argon2`      | argon2             |
| 64 hex chars   | sha256             |
| 128 hex chars  | sha512             |
| 32 hex chars   | md5                |

---

### Infinite Cracking Mode

When cracking without `--amount`, the tool enters **adaptive infinite mode**.
Supplying `--length N` makes this an exact-length infinite search; otherwise it
uses the ranked model lengths followed by the complete supported range
(`4..=32`).

In this mode the system:

1. Generates password batches
2. Attempts cracking
3. Continues from the same deterministic search space
4. Repeats until cracked

Candidate-order strategy:

- weighted model patterns, highest weight first
- unweighted model patterns, in model order
- unlisted configured Rust fallback base patterns
- one-symbol Rust-derived mutations of eligible non-symbol patterns
- two-symbol Rust-derived mutations of eligible non-symbol patterns

Each phase uses every supplied primary/secondary token and numeric value.
The Rust mutation phases insert one, then two, configured symbols before,
between, or after pattern components, even when the model did not predict a
symbol pattern. The one-symbol phase is deliberately exhausted before the
two-symbol phase because simpler single-symbol passwords are usually more
probable. Two `{symbol}` occurrences are selected independently, so mixed pairs
such as `.@` are included. Model-preferred symbols retain priority over the
Rust-owned symbol list in `config/symbols.txt`.

The fallback base-pattern list is loaded and validated once at startup from
`config/allowed_patterns.txt`. It is a runtime configuration file: use one
complete non-symbol placeholder pattern per line, keep the lines in priority
order, and use blank lines or `#` comments for annotation. Invalid, duplicate,
empty, or unreadable files stop the run before the model is called. Override the
default with `--allowed-patterns PATH` for a versioned experimental fixture.
Symbols are intentionally rejected in this file because Rust derives symbol
placements in the later one- and two-symbol phases.

Rust also derives two-digit year fragments from every four-digit numeric value
after trying the original model value: for example, `1999` adds `19` and `99`,
while `2005` adds `20` and `05`.

When a model omits numbers, Rust still supplies the bounded, ordered generic
numeric list compiled from `config/numbers.txt`. Model numbers and their
derived two-digit year fragments are always tried before those generic values.
The list accepts digit-only entries of one to four characters and can be
edited to tune the bounded fallback search space.

The finite fallback grammar supports up to two token placeholders, one
`{number}` or `{year}` placeholder, and two `{symbol}` placeholders (five
components total). This is
the explicit boundary that makes exhaustive fallback coverage reproducible;
additional values in each input list are still fully combined within it.

---

### Persona-Based Dictionaries

Instead of generic dictionaries like:
rockyou.txt

AI-PassGen produces **target-specific password sets**, dramatically reducing search space.

---

# Architecture

AI-PassGen is built using a **hybrid Rust + Python architecture**.

## Current Model Boundary

The Python process is responsible for one semantic operation: converting a
persona into a structured search-space JSON object. It does not generate
password strings. By default it calls the Hugging Face inference route for
`openai/gpt-oss-20b` that is fine tuned through an Adapter; set `HF_MODEL_ID` to use another
model or `HF_INFERENCE_URL` to use a deployed endpoint. Authentication uses
the `HF_TOKEN` environment variable.

The Rust process deserializes and validates that JSON, then expands tokens,
numbers, symbols, patterns, and case variants locally. Duplicate candidates
are removed before they are written or passed to the Rayon-based verifier.

Example model output:

```json
{
  "primary_tokens": ["Daniel"],
  "secondary_tokens": ["Arsenal"],
  "important_numbers": ["1999"],
  "preferred_symbols": ["@", "!"],
  "likely_lengths": [4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
  "likely_patterns": ["{token}{year}", "{token}{symbol}{number}"]
}
```

The model request is performed once per run. Rust owns the deterministic
expansion, phase ordering, and requested candidate limit.

### Research run records and terminal output

Each crack run writes a self-contained JSON record under `output/crack_runs/`
unless `--data-output PATH` is supplied. The record includes the persona JSON,
the configured LLM model identifier, the raw LLM response, the validated
SearchSpace Rust actually consumed, and (when a match is found) the generator
template, phase, and case variant that produced the matched candidate.

The CLI keeps concise operational output such as match/no-match status, timing,
and the run-record location. It no longer prints raw LLM responses or complete
candidate/batch lists. LLM endpoint and unexpected Python/runtime diagnostics
continue to be written to stderr for debugging. Treat crack-run records as
sensitive research artefacts because the raw response and persona can contain
identifying context.

Set `HF_TOKEN` before running the CLI when using a Hugging Face endpoint:

```text
HF_TOKEN=your_token cargo run -- --input persona_examples/sample_persona.json --length 10 --amount 20
```
