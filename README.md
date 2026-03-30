# Tequel (TQL-11)

![Crates.io Version](https://img.shields.io/crates/v/tequel-rs?style=flat-square&color=orange)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Rust](https://img.shields.io/badge/rust-v1.70%2B-black?style=flat-square&logo=rust)

*A high-performance, Register-Aware SIMD cryptographic engine and hash function, built in pure Rust for mission-critical data integrity.*

**Tequel 0.9.0: The "Iron-Clad" Performance Update.** Featuring a complete core refactor, the TQL-11 engine now utilizes **Register Pinning** and **2x Loop Unrolling**, delivering a massive **+125% throughput increase** in single-core environments and stabilizing at a rock-solid **~23 MiB/s** for large-scale data.

*By Gabriel "dotxav" Xavier (@G4brielXavier)*

## 🔬 Internal Architecture: TQL-11 (v0.9.0)

Tequel is powered by the **TQL-11**, a custom ARX (Addition-Rotation-XOR) primitive engineered for high-density bit diffusion and hardware-level efficiency.

* **Register Pinning:** Elimination of "Register Spilling" by mapping the 12 internal states directly to YMM registers, keeping all operations inside the CPU execution units and bypassing the Stack/RAM bottleneck.
* **2x Loop Unrolling:** Processes 128 bytes per iteration (interleaving two 64-byte blocks), reducing branch overhead and maximizing Instruction-Level Parallelism (ILP).
* **Dual-Wide SIMD:** Processes parallel YMM blocks using asymmetric bit-twisting (`0x517CC1B7`) to ensure unique entropy paths.
* **Zero-Allocation Hex Engine:** Optimized hexadecimal serialization using static lookup tables, delivering O(1) latency for hash output.

## 🌪️ The Physics of Chaos: Digital Product Passport (DPP)

Tequel was engineered for **Digital Product Passports (DPP)**. In industrial environments, speed is nothing without integrity. 

With a **50.14% Strict Avalanche Criterion (SAC)**, Tequel ensures that flipping a single bit in a product's telemetry or history results in a completely different hash. By running at **~23 MiB/s (Single-Core)**, it allows real-time scanning and verification on edge devices without draining battery or creating production bottlenecks.



## 📊 Performance Benchmarks (v0.9.0)

### Single-Core Evolution (Criterion)
Verified on `target-cpu=native` (AVX2).

| Metric | v0.8.0 | **v0.9.0 (Current)** | Improvement |
| :--- | :--- | :--- | :--- |
| **Small Data (1024 bytes)** | 11.10 MiB/s | **22.33 MiB/s** | **+125.5%** |
| **Medium Data (65KB)** | 10.90 MiB/s | **23.38 MiB/s** | **+114.5%** |
| **Large Data (1MB)** | 11.05 MiB/s | **23.05 MiB/s** | **+108.6%** |
| **Parallel Throughput** | ~970 MiB/s | **~1.1 GiB/s** | **+19.6%** |

### Comparative Analysis
| Algorithm | Throughput (MB/s) | Avalanche (SAC) | CPU Usage | Primary Use-Case |
| :--- | :--- | :--- | :--- | :--- |
| **SHA-256** | ~380 MB/s | 50.01% | High | High-Security / Crypto |
| **xxHash (XXH3)** | ~25,000+ MB/s | 48.20% | Ultra-Low | Checksums / HashMaps |
| **Tequel (TQL-11)** | **~23 MB/s (Core)** | **50.14%** | **Efficient** | **Industrial IoT / DPP** |

## 🛡️ Statistical Rigor

* **Strict Avalanche Criterion (SAC):** 50.14% (Ideal statistical randomness).
* **Shannon Entropy:** 7.999991 bits/byte. Output is statistically indistinguishable from white noise.
* **Memory Footprint:** Zero heap allocations during the hashing process.

## ⚙️ Core Features

* **AVX2 Pinned State**: Manual register allocation for maximum throughput.
* **Hybrid Remainder Logic**: Multi-stage cleanup (128-byte unroll -> 64-byte SIMD -> Byte-wise scalar).
* **Rayon Ready**: Native scaling for multi-threaded file integrity verification.
* **Zero Dependencies**: Pure Rust, no external overhead.

## 📥 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
tequel-rs = "0.9.0"
```

## Usage

### High-Performance Hashing

```rust
use tequel_rs::hash::TequelHash;

fn main() {
    let mut teq = TequelHash::new();
    let data = b"data_to_verify_integrity";
    
    // Generates a 384-bit secure hash string
    let hash = teq.tqlhash(data);
    println!("TQL-11 Integrity Hash: {}", hash);
}
```

## Why the name 'Tequel'?

"Tequel" is a reference from the Book of Daniel: "*Mene, Mene, Tequel, Parsim*".

**TEQUEL** means "**Weighed**". It represents a judgment where data is weighed and its integrity verified. In this library, it stands for the cryptographic weight and the balance between speed and chaos—data secured by Tequel is weighed and found impenetrable.


## License

**MIT License** - Build the future, keep it open.