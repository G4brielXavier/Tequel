# Encryption and Decryption

## Summary

- [Encryption and Decryption](#encryption-and-decryption)
  - [Summary](#summary)
  - [Encryption](#encryption)
  - [Decryption](#decryption)
  - [Using Salt and Custom Iterations](#using-salt-and-custom-iterations)



## Encryption

Encryption in Tequel is based in **Encrypt-then-MAC (EtM)**, so is following some steps here, each step has:

- XOR (Exclusive OR)
- `Wrapping Add/Sub`
- Salt
- MAC
- Difusion 
- Confusion

Fistly, it performs a mix using XOR and `Wrapping Add` with *Data (Delivered to encrypt) + Key (to decrypt) + Constants*.

Later, the **MAC** is build with:
- *Encrypted Data*
- *Key*
- *Constants*
- *Salt* (as default or delivered)

In the final, is returned a `TequelEncryption`:

```rust
pub struct TequelEncryption {
    pub encrypted_data: String,
    pub salt: String,
    pub mac: String
}
```

Here an example of use:

```rust
use tequel_rs::encrypt::{ TequelEncrypt, TequelEncryption };

fn main() {
    let mut tequel : TequelEncrypt = TequelEncrypt::new();

    let my_data_bytes: &[u8] = b"data"; // <- Here is your data
    let my_key: &str = "my_secret_key"; // <- It is the key to descrypt

    let data_encrypted: TequelEncryption = tequel.encrypt(&my_data_bytes, my_key).unwrap();

    println!("{:?}", data_encrypted);
}
```

```output
TequelEncryption { encrypted_data: "708eba6d", salt: "32333532383336363235", mac: "7a2ce6596850173d9e0e7f94e7f165d8fdfc81840051d0cb595031f888ee7d13277e7d5271374491" }
```

## Decryption

Decryption in Tequel basically consists of doing the reverse of encryption; That is the classic logic behind.

But, obviusly validations are performed:

- if MACs are different, returns a `TequelError::InvalidMac`.
- if decode actions raise an error, returns a `TequelError::InvalidHex`

The MACs are compared using ***Constant-Time Comparison***, it is done with:
- XOR (`^`): to detect differencies
- OR (`|`): as accumulator

Basically is done a iteration over MACs and compared each `byte` from both:
- If `byte` is equal then continue
- If `byte` is different then add to `accumulator`

In the final, if `accumulator` is not `0`, so MACs are wrong and the function is stopped before *decryption*.

If MACs are equal, do `decryption` and return the result as `String`.


```rust
use tequel_rs::encrypt::{ TequelEncryption, TequelEncrypt };

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut teq_crypt: TequelEncrypt = TequelEncrypt::new();

    let my_data: &str = "data";
    let my_key: &str = "secret123";

    let encrypted: TequelEncryption = teq_crypt.encrypt(&my_data.as_bytes(), my_key)?;

    let decrypted: String = teq_crypt.decrypt(&encrypted, my_key)?;

    println!("Original: {}", my_data);
    println!("Decrypted: {}", decrypted);

    Ok(())
}
```

```output
Original: data
Decrypted: data
```



## Using Salt and Custom Iterations

Now I will use `salt` and custom `iterations` for my encrypt.

```rust
use tequel_rs::encrypt::{ TequelEncrypt, TequelEncryption };
use tequel_rs::rng::TequelRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let teq_rng: TequelRng = TequelRng::new(); // I will use TequelRng to generate my random salt

    let my_salt: u32 = teq_rng.rand_deep_u32(); // a random u32

    let teq_hash: TequelEncrypt = TequelEncrypt::new()
        .with_salt(my_salt) // My random salt
        .with_iterations(100); // I will make 100 iterations

    Ok(())

}
```

With this, my *encryption* will be done together with *Salt*, something like:

Encryption Flow:
```
Key + Data + Salt + Constants = Encrypted-Data
```

Authentication Flow (MAC):
```
Encrypted-Data + Key + Constants + Salt = MAC
```

**Note on Salt:** If you don't provide a *SALT*, it doesn't matter, `TequelRng` will generate a random one by *default*.

**Note on Iterations:** While the default is set to 100, the actual number of MIX operations is dynamic. Tequel introduces subtle variations to the iteration count during each step (e.g., 110, 70, 130) to prevent *side-channel analysis* and increase security.
