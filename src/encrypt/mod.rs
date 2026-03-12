use std::num::ParseIntError;

use crate::hash::TequelHash;
use crate::error::TequelError;
use crate::rng::TequelRng;

/// TequelEncrypt is a struct that controls Encryption, it uses `Salt` and `Custom Iterations`. <br><br>
/// Your functions are:
/// - `encrypt`
/// - `decrypt`
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TequelEncrypt {
    pub salt: String,
    pub iterations: u32,
}



#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TequelEncryption {
    pub encrypted_data: String,
    pub salt: String,
    pub mac: String
}



impl TequelEncrypt {

    pub fn new() -> Self {
        Self {
            salt: "".to_string(),
            iterations: 30
        }
    }

    pub fn with_salt(mut self, salt: &str) -> Self {
        self.salt = salt.to_string();
        self
    }

    pub fn with_iteration(mut self, value: u32) -> Self{
        self.iterations = value;
        self
    }

    /// <br>
    /// 
    /// ```rust
    /// 
    /// use tequel_rs::error::TequelError;
    /// use tequel_rs::encrypt::{ TequelEncrypt, TequelEncryption };
    /// 
    /// let mut teq_encrypt : TequelEncrypt = TequelEncrypt::new();
    /// 
    /// let key: &str = "super_secret_key"; // Your key to decryption
    /// let data: &str = "hello world"; // Your data to encrypt
    /// 
    /// let encrypted: Result<TequelEncryption, TequelError> = teq_encrypt.encrypt(&data.as_bytes(), key);
    /// ```
    /// Encrypt the DATA and returns a `Result<TequelEncryption, TequelError>`
    pub fn encrypt(&mut self, data: &[u8], keyv: &str) -> Result<TequelEncryption, TequelError> {

        // If salt is 0 then generate a own
        if self.salt.as_bytes().len() == 0 {
            let tequel_rng = TequelRng::new();
            self.salt = tequel_rng.rand_by_nano().to_string();
        }
        
        let key_salt = self.salt.as_bytes(); // SALT
        let key_crypt = keyv.as_bytes(); // KEY

        // if key is empty raise an KeyError
        if key_crypt.len() == 0 {
            return Err(TequelError::KeyError("Key is empty".to_string()))
        }

        let a = 0x107912fau32.to_be_bytes(); // KEY_C
        let b = 0x220952eau32.to_be_bytes(); // KEY_D
        let c = 0x3320212au32.to_be_bytes(); // KEY_E
        let d = 0x4324312fu32.to_be_bytes(); // KEY_E
        let e = 0x5320212au32.to_be_bytes(); // KEY_E
        
        let mut res = Vec::new();

        
        for (i, &byte) in data.iter().enumerate() {

            let mut curr = byte;

            curr = curr.wrapping_add(a[i % a.len()]);
            curr = curr ^ b[i % b.len()];
            curr = curr.wrapping_add(c[i % c.len()]);
            curr = curr ^ d[i % d.len()];
            curr = curr.wrapping_add(e[i % e.len()]);
            curr = curr ^ key_crypt[i % key_crypt.len()];

            res.push(curr)

        }

        let res = res.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let salt_res = key_salt.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();


        let mut mixmac = String::new();

        mixmac.push_str(&a.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&res);
        mixmac.push_str(&b.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&c.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&salt_res);
        mixmac.push_str(&d.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&keyv);
        mixmac.push_str(&e.iter().map(|s| format!("{:02x}", s)).collect::<String>());

        let mut cus_teq_hash = TequelHash::new();
        let comb_mixmac = cus_teq_hash.dt_hash_string(&mixmac);


        Ok(TequelEncryption { encrypted_data: res, salt: salt_res, mac: comb_mixmac })

    }


    /// <br>
    /// 
    /// ```rust
    /// 
    /// use tequel_rs::error::TequelError;
    /// use tequel_rs::encrypt::{ TequelEncrypt, TequelEncryption };
    /// 
    /// let mut tequel : TequelEncrypt = TequelEncrypt::new();
    /// 
    /// let key: &str = "super_secret_key";
    /// let data: &str = "hello world";
    /// 
    /// let encrypted: TequelEncryption = tequel.encrypt(&data.as_bytes(), &key).expect("Error in Encrypt");
    /// 
    /// let decrypted: Result<String, TequelError> = tequel.decrypt(&encrypted, &key);
    /// 
    /// match decrypted {
    ///     Ok(d) => println!("{}", d),
    ///     Err(e) => println!("{}", e)
    /// }
    /// ```
    /// Decrypts a `TequelEncryption` and returns the DATA decrypted as `String`.
    pub fn decrypt(&mut self, tequel_encryption: &TequelEncryption, key: &str) -> Result<String, TequelError> {
        
        let key_encrypt_input = key.as_bytes(); // key_a
    
        // if key is empty
        if key.len() == 0 {
            return Err(TequelError::KeyError("Key is empty".to_string()))
        }

        // CONSTANTS            
        let a = 0x107912fau32.to_be_bytes(); // KEY_A
        let b = 0x220952eau32.to_be_bytes(); // KEY_B
        let c = 0x3320212au32.to_be_bytes(); // KEY_C
        let d = 0x4324312fu32.to_be_bytes(); // KEY_D
        let e = 0x5320212au32.to_be_bytes(); // KEY_E


        let mut mixmac = String::new();

        mixmac.push_str(&a.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&tequel_encryption.encrypted_data);
        mixmac.push_str(&b.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&c.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&tequel_encryption.salt);
        mixmac.push_str(&d.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&key);
        mixmac.push_str(&e.iter().map(|s| format!("{:02x}", s)).collect::<String>());

        let mut cus_teq_hash = TequelHash::new();
        let comb_mixmac = cus_teq_hash.dt_hash_string(&mixmac).to_lowercase();

        if !self.compare_macs(tequel_encryption.mac.to_lowercase().as_bytes(), comb_mixmac.as_bytes()) {
            return Err(TequelError::InvalidMac)
        }

        let mut res = Vec::new();
        
        let hash = self.decode_hex(&tequel_encryption.encrypted_data)
            .map_err(|e| TequelError::InvalidHex(e.to_string()))?;


        for (i, &byte) in hash.iter().enumerate() {

            let mut curr = byte;

            curr = curr ^ key_encrypt_input[i % key_encrypt_input.len()];
            curr = curr.wrapping_sub(e[i % e.len()]);
            curr = curr ^ d[i % d.len()];
            curr = curr.wrapping_sub(c[i % c.len()]);
            curr = curr ^ b[i % b.len()];
            curr = curr.wrapping_sub(a[i % a.len()]);

            res.push(curr)

        }


        let res = String::from_utf8(res)
            .map_err(|_| TequelError::InvalidUtf8)?;

        Ok(res)

    }






    fn decode_hex(&self, val: &str) -> Result<Vec<u8>, ParseIntError> {
        if val.len() % 2 != 0 {
            return Err("Hex string has an odd length".parse::<u8>().unwrap_err()); 
        }

        (0..val.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&val[i..i + 2], 16))
            .collect()
    }

    fn compare_macs(&self, mac_a: &[u8], mac_b: &[u8]) -> bool {
        let mut acc = 0;

        for (i, &byte) in mac_a.iter().enumerate() {
            acc = acc | byte ^ mac_b[i];
        }

        acc == 0
    }
}