# 🦊 Vulpes — Reentrancy Vulnerability Detector for Solidity

`vulpes` is a fast, compile-time static analysis CLI tool written in Rust that detects **reentrancy vulnerabilities** in Solidity smart contracts. It parses the AST using [`solang_parser`](https://crates.io/crates/solang-parser) and identifies reentrancy patterns.

---

## 🚨 What It Detects

Vulpes currently detects the following reentrancy patterns:

- `call.value(...)()` (classic unguarded external call)
- `call{value: ...}()` (inline value transfer)
- `send(...)` and `transfer(...)`
- `delegatecall()` and `callcode()`
- External calls in `if` conditions

---

## 📦 Installation

```bash
git clone https://github.com/yourname/vulpes.git
cd vulpes
cargo build
