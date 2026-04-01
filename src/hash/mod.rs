/*
 * Tequel-rs: High-Density 384-bit Cryptographic Hash Engine
 * Copyright (C) 2026 Gabriel Xavier (dotxav)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 */

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use crate::avx2_inline::{ add, loadu, or, rota_lf, rota_rg, setone_i32, setzero, xor, horiz_add_avx2 };
use std::hint::black_box;

macro_rules! teq_direct {
    ($ss:ident, $ss1:expr, $lv:expr, $lr:expr, $ymm_a1:ident) => {
        $ss = add($ss, $ymm_a1);
        $ss = or(rota_lf::<$lv>($ss), rota_rg::<$lr>($ss));
        $ss = xor($ss1, $ss);
    };
}

use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};


/// ```TequelHash``` provides hash functions, custom iterations and salt. <br><br>
#[derive(Debug, Zeroize, ZeroizeOnDrop, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TequelHash {
    pub states: [u32; 12],
    pub salt: String,
    pub iterations: u32
}

impl TequelHash {

    pub fn new() -> Self { 
        Self {
            states: [
                0x1A2B3C4D, 0x5E6F7A8B, 0x9C0D1E2F, 0x31415926,
                0x27182818, 0xDEADBEEF, 0xCAFEBABE, 0x80808080,
                0xABCDEF01, 0x456789AB, 0xFEDCBA98, 0x01234567
            ],
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

    /// Generates a unique 384-bit hexadecimal hash from the input data.
    ///
    /// This function is the core of the Tequel engine, utilizing **SIMD/AVX2** /// instructions to process data in 256-bit blocks. It is designed for 
    /// high-speed performance and maximum bit diffusion.
    ///
    /// # Performance
    /// By leveraging hardware acceleration, `tqlhash` achieves significantly lower 
    /// latency compared to scalar implementations, making it ideal for 
    /// large-scale data integrity checks and real-time obfuscation.
    ///
    /// # Determinism
    /// The algorithm is strictly deterministic. Providing the same input bytes 
    /// will always yield the exact same hexadecimal string.
    ///
    /// # Arguments
    /// * `input` - The raw data bytes (`&[u8]`) to be hashed.
    ///
    /// # Returns
    /// A 96-character hexadecimal `String` (12 x 32-bit internal states).
    ///
    /// # Example
    /// ```rust
    /// use tequel::hash::TequelHash;
    /// 
    /// let mut tequel = TequelHash::new();
    /// let data = b"secret_data";
    /// 
    /// let hash_a = tequel.tqlhash(data);
    /// let hash_b = tequel.tqlhash(data);
    /// 
    /// assert_eq!(hash_a, hash_b);
    /// println!("Hash: {}", hash_a);
    /// ```
    pub fn tqlhash(&mut self, input: &[u8]) -> String {

        self.states = [
            0x107912FA, 0x220952EA, 0x3320212A, 0x4324312F, 
            0x5320212A, 0x9E3779B1, 0x85EBCA6B, 0xAD35744D,
            0xCC2912FA, 0xEE0952EA, 0x1120212A, 0x2224312F,
        ];

        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

        let mut s0  = unsafe { setzero() };
        let mut s1  = unsafe { setzero() };
        let mut s2  = unsafe { setzero() };
        let mut s3  = unsafe { setzero() };
        let mut s4  = unsafe { setzero() };
        let mut s5  = unsafe { setzero() };
        let mut s6  = unsafe { setzero() };
        let mut s7  = unsafe { setzero() };
        let mut s8  = unsafe { setzero() };
        let mut s9  = unsafe { setzero() };
        let mut s10 = unsafe { setzero() };
        let mut s11 = unsafe { setzero() };

        let mut chunks = input.chunks_exact(128);

        for chunk in chunks.by_ref() {

            unsafe {

                let bl_a = &chunk[..64];
                let bl_b = &chunk[64..];

                let ymm_a1 = loadu(bl_a.as_ptr() as *const __m256i);
                let ymm_a2 = xor(loadu(bl_a.as_ptr().add(32) as *const __m256i), setone_i32(0x517CC1B7));

                teq_direct!(s0,  s1,  7,  25,   ymm_a1);
                teq_direct!(s1,  s2,  31, 28,   ymm_a2);
                teq_direct!(s2,  s3,  25, 7,    ymm_a1);
                teq_direct!(s3,  s4,  23, 9,    ymm_a2);
                teq_direct!(s4,  s5,  13, 19,   ymm_a1);
                teq_direct!(s5,  s6,  29, 3,    ymm_a2);
                teq_direct!(s6,  s7,  19, 13,   ymm_a1);
                teq_direct!(s7,  s8,  17, 15,   ymm_a2);
                teq_direct!(s8,  s9,  11, 21,   ymm_a1);
                teq_direct!(s9,  s10, 5,  27,   ymm_a2);
                teq_direct!(s10, s11, 3,  29,   ymm_a1);
                teq_direct!(s11, s0,  2,  30,   ymm_a2);

                let ymm_b1 = loadu(bl_b.as_ptr() as *const __m256i);
                let ymm_b2 = xor(loadu(bl_b.as_ptr().add(32) as *const __m256i), setone_i32(0x517CC1B7));

                teq_direct!(s0,  s1,  7,  25,   ymm_b1);
                teq_direct!(s1,  s2,  31, 28,   ymm_b2);
                teq_direct!(s2,  s3,  25, 7,    ymm_b1);
                teq_direct!(s3,  s4,  23, 9,    ymm_b2);
                teq_direct!(s4,  s5,  13, 19,   ymm_b1);
                teq_direct!(s5,  s6,  29, 3,    ymm_b2);
                teq_direct!(s6,  s7,  19, 13,   ymm_b1);
                teq_direct!(s7,  s8,  17, 15,   ymm_b2);
                teq_direct!(s8,  s9,  11, 21,   ymm_b1);
                teq_direct!(s9,  s10, 5,  27,   ymm_b2);
                teq_direct!(s10, s11, 3,  29,   ymm_b1);
                teq_direct!(s11, s0,  2,  30,   ymm_b2);

                s0 = xor(s0, s11);

            }

        }


        unsafe {
            self.states[0]  = self.states[0] .wrapping_add(horiz_add_avx2(s0));
            self.states[1]  = self.states[1] .wrapping_add(horiz_add_avx2(s1));
            self.states[2]  = self.states[2] .wrapping_add(horiz_add_avx2(s2));
            self.states[3]  = self.states[3] .wrapping_add(horiz_add_avx2(s3));
            self.states[4]  = self.states[4] .wrapping_add(horiz_add_avx2(s4));
            self.states[5]  = self.states[5] .wrapping_add(horiz_add_avx2(s5));
            self.states[6]  = self.states[6] .wrapping_add(horiz_add_avx2(s6));
            self.states[7]  = self.states[7] .wrapping_add(horiz_add_avx2(s7));
            self.states[8]  = self.states[8] .wrapping_add(horiz_add_avx2(s8));
            self.states[9]  = self.states[9] .wrapping_add(horiz_add_avx2(s9));
            self.states[10] = self.states[10].wrapping_add(horiz_add_avx2(s10));
            self.states[11] = self.states[11].wrapping_add(horiz_add_avx2(s11));
        }


        let remainder_128 = chunks.remainder();
        let mut chunks_64 = remainder_128.chunks_exact(64);

        for chunk in chunks_64.by_ref() {
            unsafe {

                let ymm_a1 = loadu(chunk.as_ptr() as *const __m256i);
                let ymm_a2 = xor(loadu(chunk.as_ptr().add(32) as *const __m256i), setone_i32(0x517CC1B7));

                teq_direct!(s0,  s1,  7,  25,   ymm_a1);
                teq_direct!(s1,  s2,  31, 28,   ymm_a2);
                teq_direct!(s2,  s3,  25, 7,    ymm_a1);
                teq_direct!(s3,  s4,  23, 9,    ymm_a2);
                teq_direct!(s4,  s5,  13, 19,   ymm_a1);
                teq_direct!(s5,  s6,  29, 3,    ymm_a2);
                teq_direct!(s6,  s7,  19, 13,   ymm_a1);
                teq_direct!(s7,  s8,  17, 15,   ymm_a2);
                teq_direct!(s8,  s9,  11, 21,   ymm_a1);
                teq_direct!(s9,  s10, 5,  27,   ymm_a2);
                teq_direct!(s10, s11, 3,  29,   ymm_a1);
                teq_direct!(s11, s0,  2,  30,   ymm_a2);                

            }
        }


        let final_remainder = chunks_64.remainder();

        for (idx, &byte) in final_remainder.iter().enumerate() {
            let pos = idx % 12;
            self.states[pos] = self.states[pos].wrapping_add((byte as u32) ^ 0x9E3779B1);
        }

        self.apply_final_mixer_64();

        let mut hex_buffer = vec![0u8; 96];

        for (i, &s) in self.states.iter().enumerate() {
            let bytes = s.to_be_bytes();
            for (j, &byte) in bytes.iter().enumerate() {
                let offset = (i * 8) + (j * 2);
                hex_buffer[offset] = HEX_CHARS[(byte >> 4) as usize];
                hex_buffer[offset + 1] = HEX_CHARS[(byte & 0x0f) as usize];
            }
        }
        
        unsafe { String::from_utf8_unchecked(hex_buffer) }

    }


    /// Generates a unique 384-bit hexadecimal hash from the input data.
    ///
    /// This function is the core of the Tequel engine, utilizing **SIMD/AVX2** /// instructions to process data in 256-bit blocks. It is designed for 
    /// high-speed performance and maximum bit diffusion.
    ///
    /// # Performance
    /// By leveraging hardware acceleration, `tqlhash_raw` achieves significantly lower 
    /// latency compared to scalar implementations, making it ideal for 
    /// large-scale data integrity checks and real-time obfuscation.
    ///
    /// # Determinism
    /// The algorithm is strictly deterministic. Providing the same input bytes 
    /// will always yield the exact same hexadecimal string.
    ///
    /// # Arguments
    /// * `input` - The raw data bytes (`&[u8]`).
    ///
    /// # Returns
    /// A 32-bit list `[u8; 32]` 
    ///
    /// # Example
    /// ```rust
    /// use tequel::hash::TequelHash;
    /// 
    /// let mut tequel = TequelHash::new();
    /// let data = b"secret_data";
    /// 
    /// let bytes_a = tequel.tqlhash_raw(data);
    /// let bytes_b = tequel.tqlhash_raw(data);
    /// 
    /// assert_eq!(bytes_a, bytes_b);
    /// println!("bytes: {:?}", bytes_a);
    /// ```
    pub fn tqlhash_raw(&mut self, input: &[u8]) -> [u8; 48] {

        self.states = [
            0x107912FA, 0x220952EA, 0x3320212A, 0x4324312F, 
            0x5320212A, 0x9E3779B1, 0x85EBCA6B, 0xAD35744D,
            0xCC2912FA, 0xEE0952EA, 0x1120212A, 0x2224312F,
        ];

        let mut s0  = unsafe { setzero() };
        let mut s1  = unsafe { setzero() };
        let mut s2  = unsafe { setzero() };
        let mut s3  = unsafe { setzero() };
        let mut s4  = unsafe { setzero() };
        let mut s5  = unsafe { setzero() };
        let mut s6  = unsafe { setzero() };
        let mut s7  = unsafe { setzero() };
        let mut s8  = unsafe { setzero() };
        let mut s9  = unsafe { setzero() };
        let mut s10 = unsafe { setzero() };
        let mut s11 = unsafe { setzero() };

        let mut chunks = input.chunks_exact(128);

        for chunk in chunks.by_ref() {

            unsafe {

                let bl_a = &chunk[..64];
                let bl_b = &chunk[64..];

                let ymm_a1 = loadu(bl_a.as_ptr() as *const __m256i);
                let ymm_a2 = xor(loadu(bl_a.as_ptr().add(32) as *const __m256i), setone_i32(0x517CC1B7));

                teq_direct!(s0, s1, 7, 25,   ymm_a1);
                teq_direct!(s1, s2, 31, 28,  ymm_a2);
                teq_direct!(s2, s3, 25, 7,   ymm_a1);
                teq_direct!(s3, s4, 23, 9,   ymm_a2);
                teq_direct!(s4, s5, 13, 19,  ymm_a1);
                teq_direct!(s5, s6, 29, 3,   ymm_a2);
                teq_direct!(s6, s7, 19, 13,  ymm_a1);
                teq_direct!(s7, s8, 17, 15,  ymm_a2);
                teq_direct!(s8, s9, 11, 21,  ymm_a1);
                teq_direct!(s9, s10, 5, 27,  ymm_a2);
                teq_direct!(s10, s11, 3, 29, ymm_a1);
                teq_direct!(s11, s0, 2, 30,  ymm_a2);

                let ymm_b1 = loadu(bl_b.as_ptr() as *const __m256i);
                let ymm_b2 = xor(loadu(bl_b.as_ptr().add(32) as *const __m256i), setone_i32(0x517CC1B7));

                teq_direct!(s0, s1, 7, 25,   ymm_b1);
                teq_direct!(s1, s2, 31, 28,  ymm_b2);
                teq_direct!(s2, s3, 25, 7,   ymm_b1);
                teq_direct!(s3, s4, 23, 9,   ymm_b2);
                teq_direct!(s4, s5, 13, 19,  ymm_b1);
                teq_direct!(s5, s6, 29, 3,   ymm_b2);
                teq_direct!(s6, s7, 19, 13,  ymm_b1);
                teq_direct!(s7, s8, 17, 15,  ymm_b2);
                teq_direct!(s8, s9, 11, 21,  ymm_b1);
                teq_direct!(s9, s10, 5, 27,  ymm_b2);
                teq_direct!(s10, s11, 3, 29, ymm_b1);
                teq_direct!(s11, s0, 2, 30,  ymm_b2);

                s0 = xor(s0, s11);

            }

        }


        unsafe {
            self.states[0]  = self.states[0] .wrapping_add(horiz_add_avx2(s0));
            self.states[1]  = self.states[1] .wrapping_add(horiz_add_avx2(s1));
            self.states[2]  = self.states[2] .wrapping_add(horiz_add_avx2(s2));
            self.states[3]  = self.states[3] .wrapping_add(horiz_add_avx2(s3));
            self.states[4]  = self.states[4] .wrapping_add(horiz_add_avx2(s4));
            self.states[5]  = self.states[5] .wrapping_add(horiz_add_avx2(s5));
            self.states[6]  = self.states[6] .wrapping_add(horiz_add_avx2(s6));
            self.states[7]  = self.states[7] .wrapping_add(horiz_add_avx2(s7));
            self.states[8]  = self.states[8] .wrapping_add(horiz_add_avx2(s8));
            self.states[9]  = self.states[9] .wrapping_add(horiz_add_avx2(s9));
            self.states[10] = self.states[10].wrapping_add(horiz_add_avx2(s10));
            self.states[11] = self.states[11].wrapping_add(horiz_add_avx2(s11));
        }


        let remainder = chunks.remainder();
        
        for (idx, &byte) in remainder.iter().enumerate() {
            let pos = idx % 12;
            self.states[pos] = self.states[pos].wrapping_add((byte as u32) ^ 0x9E3779B1);
        }

        self.apply_final_mixer_64();
        
        let mut bytes = [0u8; 48];

        for (i, &val) in self.states.iter().enumerate() {
            let b = val.to_be_bytes();
            bytes[i*4 .. i*4+4].copy_from_slice(&b);
        }

        bytes
    }



    /// Verifies if a given hash matches the original input data.
    ///
    /// This is a convenience function that re-hashes the provided `input` 
    /// and performs a comparison against the existing `hash` string.
    ///
    /// # Security
    /// The verification process leverages the TQL-11 SIMD engine to ensure 
    /// high-speed integrity checks. It is ideal for verifying file integrity 
    /// or checking stored credentials.
    ///
    /// # Arguments
    /// * `hash` - The pre-computed hexadecimal hash string to be verified.
    /// * `input` - The raw bytes (`&[u8]`) of the data to check.
    ///
    /// # Returns
    /// Returns `true` if the re-computed hash matches the provided one, `false` otherwise.
    ///
    /// # Example
    /// ```rust
    /// use tequel::hash::TequelHash;
    /// 
    /// let mut tequel = TequelHash::new();
    /// let data = b"secret_message";
    /// let hash = tequel.tqlhash(data);
    ///
    /// if tequel.isv_tqlhash(&hash, data) {
    ///     println!("Integrity verified: VALID!");
    /// } else {
    ///     println!("Integrity compromised: NOT VALID!");
    /// }
    /// ```
    pub fn isv_tqlhash(&mut self, hash: &String, input: &[u8]) -> bool {
        
        let new_hash = self.tqlhash(input);

        let a = new_hash.as_bytes();
        let b = hash.as_bytes();

        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for i in 0..a.len() {
            result |= black_box(a[i] ^ b[i]);
        }

        result == 0

    }


    pub fn isv_tqlhash_raw(&mut self, hash: &[u8; 48], input: &[u8]) -> bool {

        let a_bh = self.tqlhash_raw(input);

        let mut result = 0u8;

        for i in 0..48 {
            result |= black_box(a_bh[i] ^ hash[i]);
        }

        result == 0

    }



    /// Derives a high-entropy cryptographic key from a password and a salt.
    ///
    /// This function implements a **Key Derivation Function (KDF)** powered by the TQL-11 engine.
    /// It utilizes a "Key Stretching" mechanism to make brute-force and dictionary attacks 
    /// computationally expensive.
    ///
    /// # Architecture
    /// The process is **SIMD-accelerated (AVX2)**, ensuring that the computational cost 
    /// remains high for attackers (who must replicate the intensive TQL-11 rounds) while 
    /// staying efficient for legitimate local use. Every iteration triggers a non-linear 
    /// mutation with a validated 51% avalanche diffusion.
    ///
    /// # Arguments
    /// * `password` - The raw bytes of the master password (e.g., from user input).
    /// * `salt` - A unique, random value used to prevent Rainbow Table attacks.
    /// * `iterations` - The number of hashing rounds. Higher values increase resistance 
    ///   against GPU-accelerated cracking (Recommended: >1000).
    ///
    /// # Returns
    /// A 384-bit hexadecimal `String` representing the derived cryptographic key.
    ///
    /// # Example
    /// ```rust
    /// use tequel::hash::TequelHash;
    /// 
    /// fn main() {
    ///     let mut teq = TequelHash::new();
    ///     let key = teq.derive_key("master_password_123", 2048);
    ///     println!("Derived Key: {:?}", key);
    /// }
    /// ```
    pub fn derive_key(&mut self, password: &str, iterations: u32) -> [u8; 32] {

        self.iterations = if iterations > 0 { iterations } else { 30 };

        let mut derived = format!("{}{}{}", self.salt, password, self.salt);

        for i in 0..self.iterations {
            let hash_hex = self.tqlhash(derived.as_bytes());
            derived = format!("{}{}{}", i, hash_hex, self.salt);
        }

        let final_hash = self.tqlhash(derived.as_bytes());
        let bytes = hex::decode(&final_hash).expect("Error in key closing");

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[0..32]);
        key
    }



    fn apply_final_mixer_64(&mut self) {
        for r in 0..64 {
            for i in 0..12 {
                let prev = if i == 0 { 11 } else { i - 1 };
                let next = (i + 1) % 12;

                self.states[i] = self.states[i]
                    .wrapping_add(self.states[prev])
                    .rotate_left(((r % 31) as u32) + 1);
                self.states[next] ^= self.states[i].wrapping_mul(0xAD35744D);
            }
        }
    }

}