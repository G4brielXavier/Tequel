# Hashing

## Summary


- [Hashing](#hashing)
  - [Summary](#summary)
  - [Hash Functions with `&str`](#hash-functions-with-str)
    - [`dif_hash_string`](#dif_hash_string)
    - [`dt_hash_string`](#dt_hash_string)
  - [Hash Function with `&[u8]`](#hash-function-with-u8)
    - [`dif_hash_bytes`](#dif_hash_bytes)
    - [`dt_hash_bytes`](#dt_hash_bytes)
  - [Hash with Salt](#hash-with-salt)
    - [Simple `salt`](#simple-salt)
    - [Generating a random `salt`](#generating-a-random-salt)



## Hash Functions with `&str`

### `dif_hash_string`

Generates a non-deterministic HASH (unique even with the same input) with `&str` as input.

```rust
use tequel_rs::TequelHash;

fn main() {
    let mut teq_hash: TequelHash = TequelHash::new(); 

    let hash1: String = teq_hash.dif_hash_string("123");
    let hash2: String = teq_hash.dif_hash_string("123");

    println!("HASH1: {}", hash1);
    println!("HASH2: {}", hash2);
}
```

```output
HASH1: 1e330de76c53a6523c5d8cca9ff42c7be5430a4c2cc599a4b0a81f0f9567c7f541d0a92fed232026
HASH2: 58c2e9cfcc2b5acc9aa94e6702d16c91479a156bf29f896793ad439039de53cef310ba8debf46728
```


### `dt_hash_string`

Generates a deterministic HASH (same input, same output) with `&str` as input.

```rust
use tequel_rs::TequelHash;

fn main() {
    let mut teq_hash: TequelHash = TequelHash::new(); 

    let hash1: String = teq_hash.dt_hash_string("123");
    let hash2: String = teq_hash.dt_hash_string("123");

    println!("HASH1: {}", hash1);
    println!("HASH2: {}", hash2);
}
```

```output
HASH1: 319970a3340073dc2003a470be1ee25c490bc8c64f4cb394e5f53249ca79433e9955a16371374491
HASH2: 319970a3340073dc2003a470be1ee25c490bc8c64f4cb394e5f53249ca79433e9955a16371374491
```

## Hash Function with `&[u8]`

### `dif_hash_bytes`

Generates a non-deterministic HASH (unique even with the same input) with `&[u8]` as input.

```rust
use tequel_rs::TequelHash;

fn main() {
    let mut teq_hash: TequelHash = TequelHash::new(); 

    let hash1: String = teq_hash.dif_hash_bytes(b"123");
    let hash2: String = teq_hash.dif_hash_bytes(b"123");

    println!("HASH1: {}", hash1);
    println!("HASH2: {}", hash2);
}
```

```output
HASH1: 319970a3340073dc2003a470be1ee25c490bc8c64f4cb394e5f53249ca79433e9955a16371374491
HASH2: 58c2e9cfcc2b5acc9aa94e6702d16c91479a156bf29f896793ad439039de53cef310ba8debf46728
```

### `dt_hash_bytes`

Generates a deterministic HASH (same input, same output) with `&[u8]` as input.

```rust
use tequel_rs::TequelHash;

fn main() {
    let mut teq_hash: TequelHash = TequelHash::new(); 

    let hash1: String = teq_hash.dt_hash_bytes(b"123");
    let hash2: String = teq_hash.dt_hash_bytes(b"123");

    println!("HASH1: {}", hash1);
    println!("HASH2: {}", hash2);
}
```

```output
HASH1: 319970a3340073dc2003a470be1ee25c490bc8c64f4cb394e5f53249ca79433e9955a16371374491
HASH2: 319970a3340073dc2003a470be1ee25c490bc8c64f4cb394e5f53249ca79433e9955a16371374491
```








## Hash with Salt

Using a salt in HASH prevents Rainbow Table attacks and ensures that identical passwords result in different hashes.

### Simple `salt`

To use `salt` in your hash is simple, you use `with_salt()` from `Tequel::new()`.

```rust
use tequel_rs::TequelHash;

fn main() {

    let teq_hash: TequelHash = TequelHash::new()
        .with_salt("my_salt_here"); // <-- here

}
```

Now your hash will be combined with the provided salt for increased security.

### Generating a random `salt`

You can generate a `salt` with `rand_by_nano` from `TequelRng`, for example:

```rust
use tequel_rs::TequelHash;
use tequel_rs::TequelRng;

fn main() {

    // Instance TequelRng
    let teq_rng: TequelRng = TequelRng::new();

    // Instance TequelHash and use the rand_by_nano
    let tequel_hash: TequelHash = TequelHash::new()
        .with_salt(teq_rng.rand_by_nano());

}
```