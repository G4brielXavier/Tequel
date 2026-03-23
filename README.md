# Tequel (TQL-11)

![Crates.io Version](https://img.shields.io/crates/v/tequel-rs?style=flat-square&color=orange)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Rust](https://img.shields.io/badge/rust-v1.70%2B-black?style=flat-square&logo=rust)

*A high-performance, SIMD-accelerated cryptographic engine and KDF, built in pure Rust for the modern CPU.*

**Tequel 0.7.0: The Integrity & Speed Update.** Featuring a synchronized AVX2 core, the TQL-11 engine now delivers consistent **10+ MiB/s throughput** with a "Verify-then-Decrypt" architecture. Designed for local-first security, high-speed obfuscation, and low-level systems like **MyWay CLI**.

*By Gabriel "dotxav" Xavier (@G4brielXavier)*

## 🔬 Internal Architecture: TQL-11 (SIMD Edition)

Tequel is powered by the **TQL-11**, a custom ARX (Addition-Rotation-XOR) primitive re-engineered for **Single Instruction, Multiple Data (SIMD)**.

* **Vectorized Execution:** Uses **AVX2 (256-bit)** intrinsics to process 32-byte chunks in parallel.
* **Synchronized Phase Mapping:** Uses Global Indexing (`g_idx`) to ensure keystream alignment between SIMD blocks and scalar remainders.
* **Authenticated Encryption:** Implements a custom MAC (Message Authentication Code) layer that verifies data integrity before decryption begins.
* **Zero-Allocation Pipeline:** Optimized `Vec<u8>` buffers to minimize heap pressure and maximize CPU cache locality.

## 📊 Performance Benchmarks (v0.7.0)

Verified using `criterion.rs` on `target-cpu=native`.

| Operation | Data Size | Result (v0.5.x) | **Result (v0.7.0)** | Improvement |
| :--- | :--- | :--- | :--- | :--- |
| **Encryption Latency** | 1 KB | 588.8 µs | **114.0 µs** | **-80.6%** |
| **Throughput** | 1 MB | 1.74 MiB/s | **10.38 MiB/s** | **+496%** |
| **Throughput** | 5 MB | ~1.50 MiB/s | **10.32 MiB/s** | **+588%** |
| **Avalanche (SAC)** | Bit-diff | 50.26% | **51.04%** | **Optimal** |

## 🛡️ Statistical Rigor

### **1. Strict Avalanche Criterion (SAC)**
A single bit flip in the input causes a cascading change in the output.
- **Result:** **51.04%** (Near-perfect bit-flip distribution).
- **Collision Resistance:** Tested over **110M+ iterations** without collisions.

### **2. Shannon Entropy**
- **Result:** **7.999986 bits/byte**. The output is statistically indistinguishable from pure white noise, making it ideal for high-entropy key derivation.

## ⚙️ Core Features

- **SIMD Optimized**: Native AVX2 support for high-speed local encryption.
- **Authenticated Encryption**: Integrated MAC verification to prevent tampering.
- **Zero-Copy Intent**: Byte-centric API designed for zero-copy integration.
- **Memory Forensic Resistance**: Sensitive buffers are handled with security in mind.

## 📥 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tequel-rs = "0.7.0"
```

## Usage

### Authenticated Encryption & Decryption

```rust
use tequel_rs::encrypt::TequelEncrypt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut teq = TequelEncrypt::new();
    let data = b"my_data_to_protect";
    let key = "secure_master_key";

    // Encrypt returns a struct with { encrypted_data, salt, mac }
    let encrypted = teq.encrypt(data, key)?;

    // Decrypt verifies the MAC before restoring the data
    let decrypted = teq.decrypt(&encrypted, key)?;

    assert_eq!(data, decrypted.as_bytes());
    Ok(())
}
```

### Basic Hashing

```rust
use tequel_rs::hash::TequelHash;

fn main() {
  let mut teq = TequelHash::new();
  let hash = teq.tqlhash(b"data_to_hash");
}
```


## Why the name 'Tequel'?

"Tequel" is a biblical reference from the Book of Daniel: "Mene, Mene, Tequel, Parsim".

TEQUEL means "Weighed". It represents a judgment where data is weighed and its integrity verified. In this library, it stands for the cryptographic weight and the balance between speed and chaos—data secured by Tequel is weighed and found impenetrable.


## License

**MIT License** - Build the future, keep it open.

