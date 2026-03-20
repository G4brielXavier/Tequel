## tequel_rs v0.3.0

- Tests applied
    - Hashing
      - "Avalanche Test" PASS!
      - "Birthday Party" PASS! 
        - 100x more Security 
        - **+110 millions hashes generated NO COLISIONS**
      -  
    - RNG

- Changes
    - RNG
      - Removed `rand_deep_u32` and `rand_deep_u64`
      - Added `rand_deep_string`
      - Added `rand_weak_u32`
      - Improvements
  

## tequel-rs v0.4.0

- **Zeroize Memory** Applied with crate `zeroize`.
  - `TequelEncrypt` applied
  - `TequelHash` applied

- New **benchmark** for **Tequel** with `criterion`.
- Added more `derive` to `TequelHash`

- Tests
  - **Streess Test 10k Encryptions**: 
    - Passed in 0.87 sec (in `debug`)


## tequel-rs v0.4.5

- Added **benchmark** with `criterion` and `rayon`
- Tests with:
  - Latency & Throughput
  - Parallel Stress
