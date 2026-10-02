# Tequel (TQL-11)

![Crates.io Version](https://img.shields.io/crates/v/tequel-rs?style=flat-square&color=orange)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Rust](https://img.shields.io/badge/rust-v1.70%2B-black?style=flat-square&logo=rust)

> **This project is deprecated, used only for personal study purposes.**

Tequel is a high-performance integrity engine and hash function implemented in pure Rust, optimized for 4x Unrolling and AVX2-capable x86_64 architectures.

> In v2.0.0, Tequel no longer focuses on security, but rather on high integrity and raw throughput, therefore, `TequelEncrypt` has been removed.  


> **Created for personal study purposes.**

## ⚠️ Security Warning: Experimental Status

TQL-11 is a **novel and non-standard** cryptographic primitive. 
* **Not Peer-Reviewed:** This algorithm has not undergone formal cryptanalysis by third-party researchers.
* **Intended Use:** Designed for data integrity and high-speed telemetry verification in controlled environments (e.g., Industrial IoT, DPP). 
* **Disclaimer:** Do not use for high-value financial transactions or sensitive PII (Personally Identifiable Information) without understanding the risks of using non-standardized primitives.

> Tequel's focus is not security, but reliable integrity and gross flow rate.

## Technical Architecture (TQL-11)

The TQL-11 core utilizes an ARX (Addition-Rotation-XOR) primitive designed for high-density bit diffusion and hardware-level efficiency.

* **Register Pinning:** Maps internal states directly to YMM registers to minimize stack spilling and maximize execution unit utilization.
* **Loop Unrolling:** 4x loop unrolling (256 bytes per iteration) to reduce branch overhead and improve Instruction-Level Parallelism (ILP).
* **SIMD Implementation:** Parallel YMM processing with asymmetric bit-twisting for distinct entropy paths.
* **Zero-Allocation Pipeline:** Uses static lookup tables for hexadecimal serialization and memory-mapped data processing.

## Performance Benchmarks

Benchmarks conducted using Criterion on x86_64 hardware.
**Environment:** 8-core / 16-thread | `target-cpu=native` | AVX2.

### Throughput Scaling
| Payload Size | Throughput (v2.0.0) | Note |
| :--- | :--- | :--- |
| 1 MB | **7.70 GiB/s** | Single-core saturation |
| 100 MB (Parallel) | **21.92 GiB/s** | Multi-threaded (Rayon) 

## Statistical Validation

* **Strict Avalanche Criterion (SAC):** 51.14%
* **Shannon Entropy:** 7.999991 bits/byte
* **Heap Usage:** Zero dynamic allocations during hashing process
* **Determinism:** Guaranteed across x86_64-avx2 platforms
* **Collision Test:** Zero collision & ~197k hashes/s (8 bytes) in 100 million iterations

## Usage

### Rust
Add to `Cargo.toml`:
```toml
tequel-rs = "2.0.0"
```

```rust
use tequel::hash::TequelHash;

fn main() {
    let mut teq = TequelHash::new();
    let data = b"example_data";
    let hash = teq.tqlhash(data);
    println!("Hash: {}", hash);
}
```


### C Interoperability

```c
#include "tequel.h"
#include <stdio.h>

int main() {
    uint8_t input[] = "data";
    uint8_t hash[48];
    tequel_hash_raw(input, sizeof(input), hash);
    return 0;
}
```

## Benchmarking

To reproduce results on your local hardware:

Powershell:

```ps
$env:RUSTFLAGS="-C target-cpu=native"; cargo bench
```

Linux/macOS:

```bh
RUSTFLAGS="-C target-cpu=native" cargo bench
```

## Tests

```bh
cargo test -- --no-capture
```

## License

Licensed under [MIT License](./LICENSE).