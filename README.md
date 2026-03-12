# Tequel

![Crates.io Version](https://img.shields.io/crates/v/tequel-rs?style=flat-square&color=orange)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Rust](https://img.shields.io/badge/rust-v1.70%2B-black?style=flat-square&logo=rust)

*For educacional purposes only, but still usable.*

*A authenticated simetric encrypt engine (AEAD) built in Rust.*

*This project was designed to explore byte's manipulation concepts, XOR and modular-aritmetic in Rust. Not is recommended to use in high-safe systems, but yes like a tool to learn about how data can be converted and recovered through dynamic keys.*

*By Gabriel Xavier : ]*

## Summary

- [Tequel](#tequel)
  - [Summary](#summary)
  - [Security Notice](#security-notice)
  - [⚙️ What does **Tequel** do?](#️-what-does-tequel-do)
  - [📥 How to Install and Use](#-how-to-install-and-use)
  - [⁉️ Guide](#️-guide)
  - [Why the name 'Tequel'?](#why-the-name-tequel)
  - [License](#license)


## Security Notice

**Tequel** is an experimental cryptographic implementation and should not be used in production environments (if you want).





## ⚙️ What does **Tequel** do?

- **Confidentiality**: Uses XOR operations, Modular-Arithmetic, Wrapping among constants to "mask" data.
- **Integrity (MAC)**: Validates if data was modified before decryption.
- **Salting:** Generates random salts to guarantee that the same input generates different results.
- **Based in Encrypt-then-MAC (EtM)**: Smarter Security and validation of internal changes.

## 📥 How to Install and Use

1. Install with **Cargo**
```
cargo install tequel-rs
```

2. Add in your `cargo.toml`'s project

```toml
[dependencies]
tequel-rs = "0.2.2"
```

3. Use in your project

```rust
use tequel_rs::*;
```

## ⁉️ Guide

Welcome to Tequel's Guide, here you will understand how each function of Tequel works.

- [Tequel RNG](./docs/Core/RNG.md) — Low-level random number generation.
- [Tequel Hash](./docs/Core/Hashing.md) <br> — Deterministic and non-deterministic hashing.
- [Tequel Encryption](./docs/Core/Encryption.md) <br> — Authenticated encryption flow.

## Why the name 'Tequel'?

"Tequel" is a biblical reference from the *Book of Daniel*.

"Mene, Mene, **Tequel**, Parsim" — Daniel 5:25-28

This is a mysterious Aramaic phrase written by a divine hand on the wall during the Babylonian King Belshazzar's feast.

The prophet Daniel interpreted the message, which announced the end of Belshazzar's reign: *God* had numbered the kingdom, weighed the king, and divided the empire between the Medes and Persians. The kingdom fell that very night.

**TEQUEL** means "Weighed" or "Heavy." I chose this name because:

**The Mystery:** The message was "decrypted" by Daniel, a perfect metaphor for an encryption library.

**The Weight:** It represents the "heavy" security and robustness that Tequel provides to your data.

## License

**MIT License** - free to use, modify and integrate.