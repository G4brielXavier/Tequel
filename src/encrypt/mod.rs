use std::num::ParseIntError;

use crate::hash::TequelHash;
use crate::error::TequelError;
use crate::rng::TequelRng;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};


/// TequelEncrypt is a struct that controls Encryption, it uses `Salt` and `Custom Iterations`.
/// 
/// You use this struct to use encrypt in Tequel.
/// ```rust
/// use tequel_rs::encrypt::TequelEncrypt;
/// 
/// fn main() {
///     let mut teq_encrypt: TequelEncrypt = TequelEncrypt::new();
/// }
/// ```
#[derive(Debug, Zeroize, ZeroizeOnDrop, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TequelEncrypt {
    pub salt: String,
    pub iterations: u32,
}


/// `TequelEncryption` is a struct that represent final encrypt, when `TequelEncrypt` is finish, it generates a `TequelEncryption` with MAC, Salt and Encrypted Data.
/// 
/// ```rust
/// use tequel_rs::encrypt::{ TequelEncrypt, TequelEncryption };
/// 
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
/// 
///     let mut teq_encrypt: TequelEncrypt = TequelEncrypt::new();
/// 
///     // It returns a 'TequelEncryption'
///     let encrypted: TequelEncryption = teq_encrypt.encrypt("my_data".as_bytes(), "my_key_123")?;
/// 
///     Ok(())
/// }
/// ```
#[derive(Debug, Zeroize, ZeroizeOnDrop, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

    /// Encrypts a byte slice using the Tequel protocol with AVX2 acceleration.
    ///
    /// This function implements a multi-layered transformation "ladder" based on 
    /// internal constants, a random salt, and a user-provided key. It ensures 
    /// data integrity by generating a MAC (Message Authentication Code) as part 
    /// of the encryption process.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice (`&[u8]`) containing the plaintext to be encrypted.
    /// * `key` - A string slice that serves as the master key for the cipher derivation.
    ///
    /// # Returns
    ///
    /// * `Ok(TequelEncryption)` - A struct containing the hex-encoded encrypted data, 
    ///   the salt used, and the integrity MAC.
    /// * `Err(TequelError::EmptyKey)` - If the provided key string is empty.
    ///
    /// # Performance
    ///
    /// On x86_64 systems supporting **AVX2**, this function processes data in 
    /// 32-byte chunks using SIMD instructions. It automatically falls back to 
    /// a scalar implementation for the remaining bytes or unsupported hardware.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tequel_rs::encrypt::TequelEncrypt;
    ///
    /// let mut teq = TequelEncrypt::new();
    /// let secret_data = b"Tequel: Weighted and Measured";
    /// let master_key = "guard_the_gate";
    ///
    /// if let Ok(encryption) = teq.encrypt(secret_data, master_key) {
    ///     println!("Ciphertext: {}", encryption.encrypted_data);
    ///     println!("MAC: {}", encryption.mac);
    /// }
    /// ```
    pub fn encrypt(&mut self, data: &[u8], key: &str) -> Result<TequelEncryption, TequelError> {

        // If salt is 0 then generate a own
        if self.salt.as_bytes().len() == 0 {
            let tequel_rng = TequelRng::new();
            self.salt = tequel_rng.rand_by_nano().to_string();
        }
        
        let key_salt = self.salt.as_bytes(); // SALT
        let key_crypt = key.as_bytes(); // KEY

        // if key is empty raise an KeyError
        if key_crypt.len() == 0 {
            return Err(TequelError::EmptyKey("Key is empty".to_string()))
        }

        let a = 0x107912fau32.to_be_bytes(); // KEY_C
        let b = 0x220952eau32.to_be_bytes(); // KEY_D
        let c = 0x3320212au32.to_be_bytes(); // KEY_E
        let d = 0x4324312fu32.to_be_bytes(); // KEY_E
        let e = 0x5320212au32.to_be_bytes(); // KEY_E
        
        let mut res_bytes = Vec::with_capacity(data.len());

        // AVX2
        unsafe {

            if is_x86_feature_detected!("avx2") {
                let chunks = data.chunks_exact(32);
                let remainder = chunks.remainder();
                
                // let va = _mm256_set1_epi32(u32::from_be_bytes(a) as i32);
                // let vb = _mm256_set1_epi32(u32::from_be_bytes(b) as i32);
                // let vc = _mm256_set1_epi32(u32::from_be_bytes(c) as i32);
                // let vd = _mm256_set1_epi32(u32::from_be_bytes(d) as i32);
                // let ve = _mm256_set1_epi32(u32::from_be_bytes(e) as i32);

                for chunk in chunks {
                    let mut v_data = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);

                    v_data = _mm256_add_epi8(v_data, _mm256_set1_epi8(a[0] as i8));
                    v_data = _mm256_xor_si256(v_data, _mm256_set1_epi8(b[0] as i8));
                    v_data = _mm256_add_epi8(v_data, _mm256_set1_epi8(c[0] as i8));
                    v_data = _mm256_xor_si256(v_data, _mm256_set1_epi8(d[0] as i8));
                    v_data = _mm256_add_epi8(v_data, _mm256_set1_epi8(e[0] as i8));
                    
                    v_data = _mm256_xor_si256(v_data, _mm256_loadu_si256([key_crypt[0]; 32].as_ptr() as *const __m256i));

                    let mut out = [0u8; 32];
                    _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, v_data);
                    res_bytes.extend_from_slice(&out);
                
                }

                let processed_bytes = data.len() - remainder.len();

                for (i, &byte) in remainder.iter().enumerate() {
                    let gidx = processed_bytes + i;
                    let mut curr = byte;

                    curr = curr.wrapping_add(a[gidx % 4]);

                    curr = curr ^ b[gidx % 4];
                    curr = curr.wrapping_add(c[gidx % 4]);
                    curr = curr ^ d[gidx % 4];
                    curr = curr.wrapping_add(e[gidx % 4]);

                    curr = curr ^ key_crypt[gidx % key_crypt.len()];

                    res_bytes.push(curr)
                }

            }
        }



        let res = res_bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let salt_res = key_salt.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();


        let mut mixmac_buffer = Vec::with_capacity(20 + res_bytes.len() + key_salt.len() + key_crypt.len());

        mixmac_buffer.extend_from_slice(&a);
        mixmac_buffer.extend_from_slice(&res_bytes);
        mixmac_buffer.extend_from_slice(&b);
        mixmac_buffer.extend_from_slice(&c);
        mixmac_buffer.extend_from_slice(&key_salt);
        mixmac_buffer.extend_from_slice(&d);
        mixmac_buffer.extend_from_slice(&key_crypt);
        mixmac_buffer.extend_from_slice(&e);

        let mut cus_teq_hash = TequelHash::new();
        let comb_mixmac = cus_teq_hash.tqlhash(&mixmac_buffer);


        Ok(TequelEncryption { encrypted_data: res, salt: salt_res, mac: comb_mixmac })

    }


    /// Decrypts a Tequel-encrypted structure and verifies its integrity.
    ///
    /// This function performs a reverse transformation of the Tequel protocol,
    /// using AVX2 SIMD instructions when available. Before decryption, it 
    /// reconstructs the MAC (Message Authentication Code) to ensure the 
    /// ciphertext, salt, and key have not been tampered with.
    ///
    /// # Arguments
    ///
    /// * `tequel_encryption` - A reference to the [`TequelEncryption`] struct 
    ///   containing the hex-encoded data, salt, and MAC.
    /// * `key` - The string slice key used during the original encryption process.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The original plaintext as a UTF-8 string.
    /// * `Err(TequelError::InvalidMac)` - If the calculated MAC does not match 
    ///   the provided one (Integrity violation).
    /// * `Err(TequelError::InvalidUtf8)` - If the decrypted bytes are not 
    ///   valid UTF-8.
    /// * `Err(TequelError::InvalidHex)` - If the input strings are not valid hex.
    ///
    /// # Security
    ///
    /// The function follows a "Verify-then-Decrypt" pattern. If the MAC check 
    /// fails, the decryption logic is never executed, protecting against 
    /// certain types of side-channel attacks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tequel_rs::encrypt::TequelEncrypt;
    /// 
    /// fn main() {
    /// 
    ///     let mut teq = TequelEncrypt::new();
    ///     
    ///     let encrypted_obj = teq.encrypt(b"secret", "master_key").expect("Failed to encrypt");
    ///     let decrypted = teq.decrypt(&encrypted_obj, "master_key")
    ///         .expect("Failed to decrypt or verify data");
    ///
    ///     println!("Decrypted content: {}", decrypted);
    /// }
    /// ```
    pub fn decrypt(&mut self, tequel_encryption: &TequelEncryption, key: &str) -> Result<String, TequelError> {
            
        if key.is_empty() { return Err(TequelError::EmptyKey("Key is empty".to_string())); }
        
        // CONSTANTS            
        let a = 0x107912fau32.to_be_bytes(); // KEY_A
        let b = 0x220952eau32.to_be_bytes(); // KEY_B
        let c = 0x3320212au32.to_be_bytes(); // KEY_C
        let d = 0x4324312fu32.to_be_bytes(); // KEY_D
        let e = 0x5320212au32.to_be_bytes(); // KEY_E


        let encrypted_data = self.decode_hex(&tequel_encryption.encrypted_data).map_err(|e| {
            TequelError::InvalidHex(e.to_string())
        })?;

        let salt_hex = self.decode_hex(&tequel_encryption.salt).map_err(|e| {
            TequelError::InvalidHex(e.to_string())
        })?;

        let mut mixmac_buffer = Vec::with_capacity(20 + encrypted_data.len() + key.len() + salt_hex.len());

        mixmac_buffer.extend_from_slice(&a);
        mixmac_buffer.extend_from_slice(&encrypted_data);
        mixmac_buffer.extend_from_slice(&b);
        mixmac_buffer.extend_from_slice(&c);
        mixmac_buffer.extend_from_slice(&salt_hex);
        mixmac_buffer.extend_from_slice(&d);
        mixmac_buffer.extend_from_slice(&key.as_bytes());
        mixmac_buffer.extend_from_slice(&e);

        let mut cus_teq_hash = TequelHash::new();
        let comb_mixmac = cus_teq_hash.tqlhash(&mixmac_buffer).to_lowercase();

        if !self.compare_macs(tequel_encryption.mac.to_lowercase().as_bytes(), comb_mixmac.as_bytes()) {
            return Err(TequelError::InvalidMac)
        }

        // SIMD  

        let encrypted_data = self.decode_hex(&tequel_encryption.encrypted_data).map_err(|e| {
            TequelError::InvalidHex(e.to_string())
        })?;

        let mut res_bytes = Vec::with_capacity(encrypted_data.len());
        let key_encrypt_input = key.as_bytes(); // key_a

        unsafe {

            if is_x86_feature_detected!("avx2") {
                let chunks = encrypted_data.chunks_exact(32);
                let remainder = chunks.remainder();

                for (chunk_idx, chunk) in chunks.enumerate() {

                    let byte_offset = chunk_idx * 32;
                    let mut v_data = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);

                    // Key Expansion (32 bytes)
                    let mut expanded_key = [0u8; 32];
                    for i in 0..32 {
                        expanded_key[i] = key_encrypt_input[(byte_offset + i) % key_encrypt_input.len()];
                    }
                    v_data = _mm256_xor_si256(v_data, _mm256_loadu_si256(expanded_key.as_ptr() as *const __m256i));

                    v_data = _mm256_sub_epi8(v_data, _mm256_set1_epi8(e[0] as i8));
                    v_data = _mm256_xor_si256(v_data, _mm256_set1_epi8(d[0] as i8));
                    v_data = _mm256_sub_epi8(v_data, _mm256_set1_epi8(c[0] as i8));
                    v_data = _mm256_xor_si256(v_data, _mm256_set1_epi8(b[0] as i8));
                    v_data = _mm256_sub_epi8(v_data, _mm256_set1_epi8(a[0] as i8));

                    let mut out = [0u8; 32];
                    _mm256_storeu_si256(out.as_mut_ptr() as *mut __m256i, v_data);
                    res_bytes.extend_from_slice(&out);

                }

                // Remainder (Ensuring that global_idx)
                let processed_bytes = encrypted_data.len() - remainder.len();

                for (i, &byte) in remainder.iter().enumerate() {
        
                    let gidx = processed_bytes + i;
                    let mut curr = byte;
        
                    curr ^= key_encrypt_input[gidx % key_encrypt_input.len()];

                    curr = curr.wrapping_sub(e[gidx % 4]);
                    curr ^= d[gidx % 4];
                    curr = curr.wrapping_sub(c[gidx % 4]);
                    curr ^= b[gidx % 4];

                    curr = curr.wrapping_sub(a[gidx % 4]);
        
                    res_bytes.push(curr)
        
                }

            }

        }

        let res = String::from_utf8(res_bytes).map_err(|_| TequelError::InvalidUtf8)?;
        println!("{}", res);

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