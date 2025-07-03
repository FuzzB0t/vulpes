# 🦊 Vulpes — Reentrancy Vulnerability Detector for Solidity

`vulpes` is a fast, static analysis CLI tool written in Rust that detects **reentrancy vulnerabilities** in Solidity smart contracts. It parses the AST using [`solang_parser`](https://crates.io/crates/solang-parser) and identifies reentrancy patterns.

---
## Features

- Detects multiple types of reentrancy vulnerabilities.
- Supports scanning single Solidity files or entire directories.
- Outputs detailed JSON reports and human-readable summaries.
- Uses the [solang_parser](https://github.com/hyperledger-labs/solang) Rust crate for Solidity parsing.


## 🚨 What It Detects

Vulpes currently detects the following reentrancy patterns:

- `call.value(...)()` (classic unguarded external call)
- `call{value: ...}()` (inline value transfer)
- `send(...)` and `transfer(...)`
- `delegatecall()` and `callcode()`
- External calls in `if` conditions

---

## Installation

Compile the project with Rust and Cargo:

```bash
git clone https://github.com/yourusername/vulpes.git
cd vulpes
cargo build --release

Note: The compiled executable will be located in target/release/vulpes. Move or copy that to your /usr/bin/ to execute vulpes from the command-line.


