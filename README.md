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

| Hash Prefix | Detected Algorithm |
|--------------|-------------------|
| `$2a$`, `$2b$` | bcrypt |
| `$argon2` | argon2 |
| 64 hex chars | sha256 |
| 128 hex chars | sha512 |
| 32 hex chars | md5 |

---

### Infinite Cracking Mode

If no password length or amount is specified, the tool enters **adaptive infinite mode**.

In this mode the system:

1. Generates password batches
2. Attempts cracking
3. Expands the search space
4. Repeats until cracked

Search space expansion strategy:

- increase password length
- increase batch size

This allows the tool to **automatically escalate attacks**.

---

### Persona-Based Dictionaries

Instead of generic dictionaries like:
rockyou.txt


AI-PassGen produces **target-specific password sets**, dramatically reducing search space.

---

# Architecture

AI-PassGen is built using a **hybrid Rust + Python architecture**.