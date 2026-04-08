# Tequel (TQL-11)

![Crates.io Version](https://img.shields.io/crates/v/tequel-rs?style=flat-square&color=orange)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Rust](https://img.shields.io/badge/rust-v1.70%2B-black?style=flat-square&logo=rust)

Tequel is a high-performance cryptographic integrity engine and hash function implemented in pure Rust, optimized for AVX2-capable x86_64 architectures.

## Technical Architecture (TQL-11)

The TQL-11 core utilizes an ARX (Addition-Rotation-XOR) primitive designed for high-density bit diffusion and hardware-level efficiency.

* **Register Pinning:** Maps internal states directly to YMM registers to minimize stack spilling and maximize execution unit utilization.
* **Loop Unrolling:** 2x unrolling (128 bytes per iteration) to reduce branch overhead and improve Instruction-Level Parallelism (ILP).
* **SIMD Implementation:** Parallel YMM processing with asymmetric bit-twisting for distinct entropy paths.
* **Zero-Allocation Pipeline:** Uses static lookup tables for hexadecimal serialization and memory-mapped data processing.

## Performance Benchmarks

Benchmarks conducted using Criterion on x86_64 hardware.
**Environment:** 8-core / 16-thread | `target-cpu=native` | AVX2.

### Throughput Scaling
| Payload Size | Throughput (v1.1.0) | Note |
| :--- | :--- | :--- |
| 1024 bytes | 12.44 MiB/s | Setup overhead dominant |
| 1 MB | **7.89 GiB/s** | Single-core saturation |
| 100 MB (Parallel) | **25.13 GiB/s** | Multi-threaded (Rayon) |

### Comparative Analysis (Single-Core 1MB)
| Algorithm | Throughput | Implementation |
| :--- | :--- | :--- |
| SHA-384 | ~604 MiB/s | Standard ARX |
| **Tequel (TQL-11)** | **~7.89 GiB/s** | **Native AVX2** |

## Statistical Validation

* **Strict Avalanche Criterion (SAC):** 50.14%
* **Shannon Entropy:** 7.999991 bits/byte
* **Heap Usage:** Zero dynamic allocations during hashing process
* **Determinism:** Guaranteed across x86_64-avx2 platforms

## Usage

### Rust
Add to `Cargo.toml`:
```toml
tequel-rs = "1.2.0"
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

```ps
$env:RUSTFLAGS="-C target-cpu=native"; cargo bench
```


## Etymology

"Tequel" refers to the concept of "being weighed" (Daniel 5:27), representing the verification of data integrity.


## License

Licensed under AGPLv3. For commercial licensing or closed-source integrations, contact dotxavket@gmail.com.