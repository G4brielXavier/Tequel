# Random Number Generator

## Summary

- [Random Number Generator](#random-number-generator)
  - [Summary](#summary)
  - [Time](#time)
    - [`rand_by_nano`](#rand_by_nano)
  - [LGC (Linear Congruential Generator)](#lgc-linear-congruential-generator)
    - [`rand_lgc`](#rand_lgc)
  - [From Hardware/OS](#from-hardwareos)
    - [`rand_deep_u32` \& `rand_deep_u64`](#rand_deep_u32--rand_deep_u64)
  - [Range](#range)
    - [`rand_in_range_by_deep`](#rand_in_range_by_deep)
    - [`rand_in_range_by_nano`](#rand_in_range_by_nano)


## Time

### `rand_by_nano`

Generates a combination of random numbers from `SystemTime::subsec_nanos` combined with four constants (`u32`).

```rust
use tequel_rs::rng::TequelRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let tequel_rng: TequelRng = TequelRng::new();

    let rand = tequel_rng.rand_by_nano();

    println!("{}", rand);

    Ok(())

}
```

```bash
2045930856
```


## LGC (Linear Congruential Generator)

### `rand_lgc`

Generates a number from a `seed` delivered as parameter. If `seed` is equal, number will be equal too.

```rust
use tequel_rs::rng::TequelRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let tequel_rng: TequelRng = TequelRng::new();

    let seed: u32 = 2026; // <-- Your seed

    let rand1: u32 = tequel_rng.rand_lgc(seed);
    let rand2: u32 = tequel_rng.rand_lgc(seed);

    println!("NUM1: {}", rand1);
    println!("NUM2: {}", rand2);

    Ok(())

}
```

```bash
NUM1: 77654757
NUM2: 77654757
```


## From Hardware/OS

### `rand_deep_u32` & `rand_deep_u64`



Generates a set of numbers from `getrandom::getrandom` lib, that is used to get *Network noises*, *Keyboard* and others hardware's information. After it is converted to `u32` or `u64`.

```rust
use tequel_rs::rng::TequelRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let tequel_rng: TequelRng = TequelRng::new();

    let rand1: u32 = tequel_rng.rand_deep_u32();
    let rand2: u64 = tequel_rng.rand_deep_u64();

    println!("u32 rand: {}", rand1);
    println!("u64 rand: {}", rand2);

    Ok(())

}
```

```bash
u32 rand: 1757204654
u64 rand: 2850651840589006354
```


## Range 

### `rand_in_range_by_deep`

Generates a number between `min` and `max` using `rand_deep_u32`.


```rust
use tequel_rs::rng::TequelRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let tequel_rng: TequelRng = TequelRng::new();
    let mut r = String::new();

    // I will generate 10 numbers
    for _ in 0..9 {
        // Generate number between 0 and 10
        let n = tequel_rng.rand_in_range_by_deep(0, 10);
        
        let p = format!("{} ", n);
        r.push_str(&p);
    }

    println!("{}", r);

    Ok(())

}
```

```bash
9 2 1 10 9 2 5 2 6
```

### `rand_in_range_by_nano`

Generates a number between `min` and `max` using `rand_by_nano`.


```rust
use tequel_rs::rng::TequelRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let tequel_rng: TequelRng = TequelRng::new();
    let mut r = String::new();

    // I will generate 10 numbers
    for _ in 0..9 {
        // Generate number between 10 and 500
        let n = tequel_rng.rand_in_range_by_nano(10, 500);
        
        let p = format!("{} ", n);
        r.push_str(&p);
    }

    println!("{}", r);

    Ok(())

}
```

```bash
252 492 80 450 199 166 40 316 343
```


