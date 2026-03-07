# Tequel

*For educacional purposes only, but still usable.*

*A authenticated simetric encrypt engine (AEAD) built in Rust.*

*This project was designed to explore byte's manipulation concepts, XOR and modular-aritmetic in Rust. Not is recommended to use in high-safe systems, but yes like a tool to learn about how data can be converted and recovered through dynamic keys.*

*By Gabriel Xavier : ]*

## Summary

- [Tequel](#tequel)
  - [Summary](#summary)
  - [Security Notice](#security-notice)
  - [⚙️ What **Tequel** do?](#️-what-tequel-do)
  - [📥 How to install and Use](#-how-to-install-and-use)
  - [💻 How to use?](#-how-to-use)
  - [Random](#random)
    - [Simple Random](#simple-random)
  - [🔒🔢 Hashing](#-hashing)
    - [Different HASH](#different-hash)
    - [UNIQUE HASH](#unique-hash)
    - [UNIQUE HASH + Random Salt](#unique-hash--random-salt)
    - [UNIQUE HASH + Custom Salt](#unique-hash--custom-salt)
  - [🔐 Encryption and Decryption](#-encryption-and-decryption)
    - [Encryption with `teq_encrypt`](#encryption-with-teq_encrypt)
    - [Decryption with `teq_decrypt`](#decryption-with-teq_decrypt)
  - [License](#license)


## Security Notice

**Tequel** is an experimental cryptographic implementation and should not be used in production environments.





## ⚙️ What **Tequel** do?

- **Confiability**: Uses XOR operations and Modular-Arithmetic to "mask" data.
- **Integrity (MAC)**: Validates if data was modified before decryption.
- **Salting**: Generates random salts to guarante that same password generate different results.

## 📥 How to install and Use

1. Install with **Cargo**
```
cargo install tequel-rs
```

2. Add in your `cargo.toml`'s project

```
tequel-rs = "0.1.0"
```

3. Import in your project

```rust
use tequel_rs::Tequel;
```

## 💻 How to use?

```rust
// Quick example

use tequel_rs::{ TequelEncryption, Tequel };

fn main() {
    let mut tequel : Tequel = Tequel::new();
}
```

## Random

### Simple Random

```rust
use tequel_rs::Tequel;

fn main() {
    let mut tequel = Tequel::new();

    let my_id: String = tequel.rand_mini();

    println!("{}", my_id);
}
```

Output:

```
34390ff2
```


More functions to RNG soon...


## 🔒🔢 Hashing

- `df_hash`: Generates a different HASH for each call. (No matter INPUT).
- `dt_hash`: Generates a unique HASH for a INPUT. 



### Different HASH

```rust
use tequel_rs::Tequel;

fn main() {
    let mut tequel = Tequel::new();

    let hash1: String = tequel.df_hash("123");
    let hash2: String = tequel.df_hash("123");

    println!("HASH1: {}", hash1);
    println!("HASH2: {}", hash2);
}
```

```output
HASH1: 1e330de76c53a6523c5d8cca9ff42c7be5430a4c2cc599a4b0a81f0f9567c7f541d0a92fed232026
HASH2: 58c2e9cfcc2b5acc9aa94e6702d16c91479a156bf29f896793ad439039de53cef310ba8debf46728
```


### UNIQUE HASH

```rust
use tequel_rs::Tequel;

fn main() {
    let mut tequel = Tequel::new();

    let hash1: String = tequel.dt_hash("123");
    let hash2: String = tequel.dt_hash("123");

    println!("HASH1: {}", hash1);
    println!("HASH2: {}", hash2);
}
```

```output
HASH1: 319970a3340073dc2003a470be1ee25c490bc8c64f4cb394e5f53249ca79433e9955a16371374491
HASH2: 319970a3340073dc2003a470be1ee25c490bc8c64f4cb394e5f53249ca79433e9955a16371374491
```


### UNIQUE HASH + Random Salt


```rust
use tequel_rs::{ Tequel, TequelSHash };

fn main() {
    let mut tequel = Tequel::new();

    let hash_salt: TequelSHash = tequel.slgen_hash("banana");


    println!("HASH: {:?}", hash_salt);
}
```

```output
HASH: TequelSHash { salt: "0528547e", hash: "1f56cd5a9d2e60b117107d2c1f0267e546684ac68bc1a73b9816d46420b970a1a13edcc671374491" }
```


### UNIQUE HASH + Custom Salt


```rust
use tequel_rs::{ Tequel, TequelSHash };

fn main() {
    let mut tequel = Tequel::new();

    let my_salt: &str = "yellow";
    let hash_salt: TequelSHash = tequel.slcus_hash("banana", &my_salt);


    println!("HASH: {:?}", hash_salt);
}
```

```output
HASH: TequelSHash { salt: "yellow", hash: "b42de9b670a2fb62d0e1239b65e71140298fc07a2b14818a54623ebc576576c5593ca0fe71374491" }
```







## 🔐 Encryption and Decryption


### Encryption with `teq_encrypt`

```rust
use tequel_rs::{ Tequel, TequelEncryption };

fn main() {
    let mut tequel = Tequel::new();

    let crypt: TequelEncryption = tequel.teq_encrypt("MY_SECRET", "pass123");

    println!("CRYPT: {:?}", crypt);
}
```

```output
CRYPT: TequelEncryption { data: "9504f49d243ff5cd9d", salt: "3861306562636666", key: "pass123", mac: "f9e50b94f68388958eae9d2e63b1862ef12495a835c38fa8d9fbf23ca850680b95b4292471374491" }
```

It returns a `TequelEncryption`

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct TequelEncryption {
    pub data: String,
    pub salt: String,
    pub key: String,
    pub mac: String
}
```

- `data`: Hash
- `salt`: Randomic Hash Salt for Salting
- `key`: Key to decryption
- `mac`: EtM (Encrypt-then-MAC). It is to validade modifications in HASH

### Decryption with `teq_decrypt`

```rust
use tequel_rs::{ Tequel, TequelEncryption };

fn main() {
    let mut tequel = Tequel::new();

    let crypt: TequelEncryption = tequel.teq_encrypt("MY_SECRET", "pass123");
    let decrypt: String = match tequel.teq_decrypt(&crypt) {
        Ok(d) => d,
        Err(e) => {
            println!("{}", e);
            String::from("ERROR")
        }
    };

    println!("CRYPT: {:?}", crypt);
    println!("DECRYPT: {:?}", decrypt);
}
```

```output
CRYPT: TequelEncryption { data: "9d05c5f8543dc4cd95", salt: "3066613832613766", key: "pass123", mac: "7cddcee8f68388958eae9d2e63b1862ef12495a835c38fa8d9fbf23ca850680b95b4292471374491" }
DECRYPT: "MY_SECRET"
```


The `mac` is verified in start of `teq_decrypt`, before the main process to validade if the HASH was not modified.


## License

**MIT License** - free to use, modify and integrate.