# AI-PassGen

### Persona-Guided Candidate Search and Hash Verification Research Tool

AI-PassGen is a **research-oriented password-analysis tool**. It asks an LLM to infer a compact, structured search space from a persona, then uses Rust to deterministically expand and verify password candidates.

The tool combines:

- persona-driven LLM search-space inference
- deterministic, model-first candidate expansion in Rust
- multithreaded local hash verification
- bounded exhaustive cracking when no candidate limit is supplied

Unlike a generic brute-force engine, AI-PassGen uses persona attributes to prioritise candidate components and patterns. The LLM does not return password strings; Rust owns all candidate rendering, deduplication, ordering, and verification.

This project is part of a **cybersecurity research study investigating intelligent password generation strategies**.

---

# Table of Contents

- [Overview](#overview)
- [How candidate search works](#how-candidate-search-works)
- [Architecture](#architecture)
- [Requirements and setup](#requirements-and-setup)
- [Installation](#installation)
- [Usage](#usage)
- [Modes of Operation](#modes-of-operation)
- [Command Line Options](#command-line-options)
- [Supported Hash Algorithms](#supported-hash-algorithms)
- [Project Structure](#project-structure)
- [Run records and troubleshooting](#run-records-and-troubleshooting)
- [Tests](#tests)
- [Security & Ethical Use](#security--ethical-use)

---

# Overview

Traditional password cracking tools rely on:

- brute force
- wordlists
- rule-based mutations

AI-PassGen uses an LLM to infer likely password components and patterns from persona attributes such as:

- names
- hobbies
- favorite teams
- pets
- locations
- interests
- personal dates

This mimics how **real attackers build targeted password dictionaries during OSINT-based attacks**.

Rust then exhaustively renders candidates within the configured grammar and tests them against a supplied hash using a local verification engine.

---

# How Candidate Search Works

### LLM Search-Space Inference

The LLM turns persona attributes into validated token, number, symbol, length, pattern, and pattern-weight hints. Rust never accepts free-form candidate strings from the model.

Examples of persona attributes:

- Name
- Pet name
- Favorite movie
- Favorite sport
- Hometown
- Graduation year
- Hobbies

Those hints rank the deterministic Rust search; they do not limit its configured fallback coverage.

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

### Bounded Exhaustive Cracking Mode

When cracking without `--amount`, the tool enters **bounded exhaustive mode**.
Supplying `--length N` makes this an exact-length bounded exhaustive search; otherwise it
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
- literal configured Rust fallback base patterns
- generated fallback token-sequence patterns
- one-symbol Rust-derived mutations of eligible non-symbol patterns
- two-symbol Rust-derived mutations of eligible non-symbol patterns

Each phase uses every supplied primary/secondary token and numeric value.
`{token}` is a backwards-compatible alias for `{token1}`. Distinct indexed
slots (`{token1}`, `{token2}`, `{token3}`, ...) independently select from the
complete combined token pool; repeating the same index reuses its selected
token. Thus three slots explore every ordered triple, including repeated token
values.
The Rust mutation phases insert one, then two, configured symbols before,
between, or after pattern components, even when the model did not predict a
symbol pattern. The one-symbol phase is deliberately exhausted before the
two-symbol phase because simpler single-symbol passwords are usually more
probable. Two `{symbol}` occurrences are selected independently, so mixed pairs
such as `.@` are included. Model-preferred symbols retain priority over the
Rust-owned symbol list in `config/symbols.txt`.

The fallback base-pattern list is loaded and validated once at startup from
`config/allowed_patterns.txt`. It accepts literal non-symbol patterns and two
fallback-only macros: `{token_sequence}` expands every token arity, and
`{token_sequence_with_number}` additionally inserts one `{number}` at every
token boundary. Keep entries in priority order and use blank lines or `#`
comments for annotation. Invalid, duplicate, empty, or unreadable files stop
the run before the model is called. Override the default with
`--allowed-patterns PATH` for an alternate validated file. Symbols remain
rejected in this file because Rust derives every one- and two-symbol placement
in the later phases.

Rust also derives two-digit year fragments from every four-digit numeric value
after trying the original model value: for example, `1999` adds `19` and `99`,
while `2005` adds `20` and `05`.

When a model omits numbers, Rust still supplies the bounded, ordered generic
numeric list compiled from `config/numbers.txt`. Model numbers and their
derived two-digit year fragments are always tried before those generic values.
The list accepts digit-only entries of one to four characters and can be
edited to tune the bounded fallback search space.

The finite fallback grammar supports one through `N` token placeholder
occurrences, one `{number}` or `{year}` placeholder, and two `{symbol}`
placeholders (`N + 3` components at most). `N` is selected with
`--max-token-slots N` (default `6`, maximum `32`). For exact/ranked lengths,
Rust uses the actual token lengths to prioritize the first token arity that can
reach those lengths; ASCII arities that cannot fit any requested length are
pruned. Model patterns are still always exhausted first. This remains
exhaustive only within the selected cap, length range, numeric alphabet, symbol
alphabet, and allowed fallback grammar.

---

### Persona-Based Dictionaries

Instead of generic dictionaries like:
rockyou.txt

AI-PassGen produces **target-specific password sets**, dramatically reducing search space.

---

# Architecture

AI-PassGen has a narrow model boundary: Python obtains semantic hints from the
configured endpoint, while Rust owns every candidate-rendering and
hash-verification step.

```text
persona JSON
    |
    v
ai_logic/main.py
    |
    +-- ai_logic/generator.py -- OpenAI-compatible Hugging Face endpoint
    |                              (one structured SearchSpace response)
    v
src/main.rs
    |
    +-- src/search_space.rs -- schema and grammar validation
    +-- src/expander.rs     -- deterministic candidate expansion
    +-- src/cracker.rs      -- Rayon-parallel local verification
    +-- src/telemetry.rs    -- sensitive per-run JSON record
```

## Python: semantic inference

`ai_logic/main.py` reads a persona JSON object. `ai_logic/generator.py` sends
that persona to the configured OpenAI-compatible Hugging Face Inference Endpoint
and requests one strict JSON response at temperature `0.0`. It does not ask the
model to emit password strings.

The endpoint configuration is read from the project-root `.env` file:

```text
HF_INFERENCE_URL=https://your-endpoint.example
HF_TOKEN=your_token
# Optional; defaults to openai/gpt-oss-20b
HF_MODEL_ID=your-model-id
```

Python writes one machine-readable envelope to stdout containing the persona,
model identifier, raw model response, and a `SearchSpace` with seven fields:
`primary_tokens`, `secondary_tokens`, `important_numbers`,
`preferred_symbols`, `likely_patterns`, `likely_lengths`, and
`pattern_weights`. Endpoint and Python diagnostics go to stderr so Rust never
has to parse terminal prose.

## Rust: deterministic execution

Rust validates the model envelope and fallback grammar, then expands tokens,
numbers, symbols, patterns, and case variants locally. Duplicate candidates are
removed before they are written or passed to the Rayon-based verifier.

| Module | Responsibility |
| --- | --- |
| `src/search_space.rs` | Validates the grammar, model values, and token-slot bounds; loads fallback configuration. |
| `src/expander.rs` | Produces the ordered model-first/fallback candidate stream with provenance. |
| `src/cracker.rs` | Locally verifies MD5, SHA-256, SHA-512, bcrypt, and Argon2 candidates. |
| `src/hash_detect.rs` | Detects a supported hash type when `--algo` is omitted. |
| `src/telemetry.rs` | Persists crack-run metrics and match provenance. |

# Run Records and Troubleshooting

Each crack run writes a self-contained JSON record under `output/crack_runs/`
unless `--data-output PATH` is supplied. The record includes the persona JSON,
the LLM model identifier/raw response, the validated SearchSpace Rust actually
consumed, both candidates generated and the actual hash-verification calls that
started, plus the matched search phase/template/case variant on success.

Thread fields now distinguish configured worker count, active Rayon workers,
available logical CPUs, and `threads_utilization`. The latter is explicitly
`active_worker_threads / configured_threads`; it is not operating-system CPU
utilisation. In iterative mode, active workers are the peak seen in any
verification batch.

The CLI keeps concise operational output such as match/no-match status, timing,
and the run-record location. It no longer prints raw LLM responses or complete
candidate/batch lists. LLM endpoint and unexpected Python/runtime diagnostics
continue to be written to stderr for debugging. Treat crack-run records as
sensitive research artefacts because the raw response and persona can contain
identifying context.

## Common problems

- In Git Bash, use `./persona_examples/sample_persona.json`, not
  `/persona_examples/sample_persona.json`. A leading `/` resolves beneath the
  Git installation rather than this repository.
- If `HF_INFERENCE_URL` or `HF_TOKEN` is missing, add it to the project-root
  `.env` file described above.
- If Python reports a missing package, install `ai_logic/requirements.txt` in
  the project virtual environment.
- “Search space exhausted” means no match was found inside the selected bounded
  grammar and length policy; it does not mean every possible password was tried.

# Requirements and Setup

- Rust and Cargo (this is an edition 2024 project).
- Python 3 with `venv` support.
- An OpenAI-compatible Hugging Face Inference Endpoint.
- A token authorised to use that endpoint.

The required endpoint settings are shown in the Architecture section. Keep the
project-root `.env` file private and out of source control.

# Installation

From the repository root, create the Python environment, install its
dependencies, and build the Rust binary:

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r ai_logic\requirements.txt
cargo build
```

On macOS or Linux, use `venv/bin/python` instead. Rust can create a missing
virtual environment automatically, but it does not install the Python packages.

# Usage

Run commands from the repository root. The following uses the sample persona
with a project-relative path.

Generate a bounded candidate file without verifying a hash:

```powershell
cargo run -- --input .\persona_examples\sample_persona.json --length 12 --amount 2000
```

Run a finite crack with a fixed candidate budget:

```powershell
cargo run -- --crack <HASH> --algo sha256 --input .\persona_examples\sample_persona.json --length 17 --amount 10000 --threads 4
```

Run exact-length bounded exhaustive mode by omitting `--amount`:

```bash
cargo run -- --crack <HASH> --algo sha256 --input ./persona_examples/sample_persona.json --length 17
```

Without `--length`, cracking uses model-ranked lengths followed by the complete
supported range (`4..=32`). Non-cracking generation defaults to a length of
`12` and an amount of `2000`.

# Modes of Operation

| Mode | Trigger | Behaviour |
| --- | --- | --- |
| Candidate generation | No `--crack` | Calls the model once and writes up to `--amount` candidates to an output text file. |
| Finite cracking | `--crack` and `--amount N` | Generates one ordered prefix of at most `N` candidates and verifies it locally. |
| Bounded exhaustive cracking | `--crack` without `--amount` | Generates increasingly large ordered batches until a match or the bounded search space is exhausted. |

# Command Line Options

| Option | Purpose |
| --- | --- |
| `--input PATH` | Persona JSON. Required for crack mode. |
| `--output PATH` | Candidate-output path for generation mode. |
| `--length N` | Exact candidate length, from 1 to 32. |
| `--amount N` | Candidate budget; omitting it in crack mode enables bounded exhaustive mode. |
| `--crack HASH` | Target hash to verify locally. |
| `--algo NAME` | `md5`, `sha256`, `sha512`, `bcrypt`, or `argon2`. Use this when detection is ambiguous. |
| `--threads N` | Maximum local verifier workers; default is detected logical CPUs. |
| `--allowed-patterns PATH` | Alternate validated non-symbol fallback-pattern file. |
| `--max-token-slots N` | Indexed-token cap from 1 to 32; default 6. |
| `--data-output PATH` | Explicit path for the crack-run JSON record. |
| `--condition`, `--persona-id`, `--observed-length`, `--observed-pattern` | Optional research labels recorded with a crack run. |

Run `cargo run -- --help` for the authoritative CLI help.

# Supported Hash Algorithms

| Algorithm | Detection when `--algo` is omitted |
| --- | --- |
| MD5 | 32 hexadecimal characters |
| SHA-256 | 64 hexadecimal characters |
| SHA-512 | 128 hexadecimal characters |
| bcrypt | `$2a$`, `$2b$`, or `$2y$` prefix |
| Argon2 | `$argon2` prefix |

For fast digests, hexadecimal input is normalised to lowercase. bcrypt and
Argon2 verify against their embedded parameters and salts, so they are much
slower than MD5 or SHA-family tests.

# Project Structure

```text
ai_passgen/
├── ai_logic/
│   ├── generator.py        # Endpoint request, JSON extraction, Python validation
│   ├── main.py             # Persona input and stdout generation envelope
│   └── requirements.txt
├── config/
│   ├── allowed_patterns.txt
│   ├── numbers.txt
│   └── symbols.txt
├── persona_examples/
│   └── sample_persona.json
├── src/
│   ├── main.rs
│   ├── search_space.rs
│   ├── expander.rs
│   ├── cracker.rs
│   ├── hash_detect.rs
│   └── telemetry.rs
└── output/
    └── crack_runs/         # Sensitive records, created on demand
```

# Tests

The local suite covers grammar validation, multi-token expansion, model-first
ordering, fallback coverage, symbol mutation, hash verification, run metrics,
and Python-side token-slot validation.

```powershell
cargo test
.\venv\Scripts\python.exe -m unittest discover -s ai_logic -p "test_*.py"
```

# Security & Ethical Use

Use this project only with synthetic data, explicit authorisation, or systems
you own and are permitted to assess. Do not send real personal data to the
configured endpoint without an appropriate legal basis and consent. Protect
`.env`, persona files, target hashes, generated candidate files, and crack-run
records as sensitive material.
