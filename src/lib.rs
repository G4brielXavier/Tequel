use std::{num::ParseIntError, time::SystemTime};


/// Represents return's structure of a TequelSaltHash function
#[derive(Debug, Clone, PartialEq)]
pub struct TequelSHash {
    pub salt: String,
    pub hash: String
}

/// Represents return's structure of a TequelEncrypt function
#[derive(Debug, Clone, PartialEq)]
pub struct TequelEncryption {
    pub data: String,
    pub salt: String,
    pub mac: String,
    key: String,
}



/// Tequel provides a simple AEAD-style encryption system
/// combining symmetric encryption with message authentication.
///
/// ### Example
///
/// ```
/// use tequel::Tequel;
///
/// let tequel: Tequel = Tequel::new();
///     
/// ```
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Tequel {
    /// The Hash is 40 bytes, so is necessary 10 big states u32 
    states: [u32; 10]
}


impl Tequel {
    pub fn new() -> Self {
        Self {
            states: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
                0x428a2f98, 0x71374491
            ]
        }
    }

    // RANDOMICS

    /// Generates a randomic combination of 8 bytes with letters and numbers 
    pub fn rand_mini(&self) -> String {

        let mut state_a: u32 = 0x71374491;
        let mut state_b: u32 = 0x5be0cd19;

        let now = SystemTime::now();


        if let Ok(dur) = now.duration_since(SystemTime::UNIX_EPOCH) {
            let nanos = dur.subsec_nanos();
            let bytes_nanos = nanos.to_be_bytes();

            for &byte in bytes_nanos.iter() {
                state_a = state_a.wrapping_add(byte as u32);
                state_b = (state_b ^ state_a).rotate_left(13);
            }

        };
        
        format!("{:08x}", state_b)
    }




    /// ### Tequel Different HASH
    /// ```
    /// let tequel : Tequel = Tequel::new();
    /// 
    /// let msg: &str = "hello world";
    /// 
    /// let encrypted: TequelSHash = tequel.df_hash(&msg);
    /// ```
    /// Generates a different for each calling, the input no matter
    pub fn df_hash(&mut self, input: &str) -> String {

        let byteinput = input.as_bytes();

        // Iterate over each byte in byteinput
        for byte in byteinput.iter() {
            
            // Start XOR in first state with first byte
            self.states[0] = self.states[0].wrapping_add(*byte as u32);

            // XOR in next states with the current and ROTATE to left 7 times the bytes
            for i in 0..9 {
                self.states[i + 1] = (self.states[i + 1] ^ self.states[i]).rotate_left(7)
            }

            self.states[0] = (self.states[0] ^ self.states[9]).rotate_left(11)

        }


        for _ in 0..16 {

            for i in 0..9 {
                self.states[i] = (self.states[i + 1] ^ self.states[i]).rotate_left(13);
            }

        }

        self.states.iter().map(|s| format!("{:08x}", s)).collect::<String>()

    }


    /// ### Tequel UNIQUE HASH
    /// ```
    /// let tequel : Tequel = Tequel::new();
    /// 
    /// let msg: &str = "hello world";
    /// 
    /// let encrypted: TequelSHash = tequel.dt_hash(&msg);
    /// ```
    /// Generates a unique HASH to the same INPUT
    pub fn dt_hash(&mut self, input: &str) -> String {

        self.states = Self::new().states;
        
        let byteinput = input.as_bytes();

        for byte in byteinput.iter() {

            self.states[0] = self.states[0].wrapping_add(*byte as u32);

            for i in 0..9 {
                self.states[i] = (self.states[i + 1] ^ self.states[i]).rotate_left(9)
            }

            self.states[0] = (self.states[0] ^ self.states[9]).rotate_left(17)

        }

        for _ in 0..16 {

            for i in 0..9 {
                self.states[i] = (self.states[i + 1] ^ self.states[i]).rotate_left(13);
            }

        }

        self.states.iter().map(|s| format!("{:08x}", s)).collect::<String>()

    }



    /// ### Tequel Random Salt Hash
    /// ```
    /// let tequel : Tequel = Tequel::new();
    /// 
    /// let msg: &str = "hello world";
    /// 
    /// let encrypted: TequelSHash = tequel.slgen_hash(&msg);
    /// ```
    /// Generates a unique HASH with a RANDOM SALT implemented over INPUT. It returns a TequelSHash with .salt and .hash 
    pub fn slgen_hash(&mut self, input: &str) -> TequelSHash {
        let salt = self.rand_mini();

        let combined = format!("{}{}", input, salt);
        let hash = self.dt_hash(&combined);

        TequelSHash { salt: salt, hash: hash }
    }

    /// ### Tequel Custom Salt Hash
    /// ```
    /// let tequel : Tequel = Tequel::new();
    /// 
    /// let mysalt: &str = "banana";
    /// let msg: &str = "hello world";
    /// 
    /// let encrypted: TequelSHash = tequel.slcus_hash(&msg, &mysalt);
    /// ```
    /// Generates a unique HASH with a CUSTOM SALT implemented over INPUT. It returns a TequelSHash with .salt and .hash
    pub fn slcus_hash(&mut self, input: &str, salt: &str) -> TequelSHash {
        let combined = format!("{}{}", input, &salt);
        let hash = self.dt_hash(&combined);

        TequelSHash { salt: salt.to_string(), hash }
    }




    // VALIDATION

    /// Validates if TequelSHash is valid with INPUT or not
    pub fn is_valid_sl_hash(&mut self, inputkey: &str, hash_tequel: &TequelSHash) -> bool {
        let validhash = self.slcus_hash(inputkey, &hash_tequel.salt);

        if validhash.hash == hash_tequel.hash {
            true
        } else {
            false
        }
    }




    /// ### Tequel Encryption
    /// ```
    /// let tequel : Tequel = Tequel::new();
    /// 
    /// let key: &str = "super_secret_key";
    /// let msg: &str = "hello world";
    /// 
    /// let encrypted: TequelEncryption = tequel.teq_encrypt(&msg, &key);
    /// ```
    /// Encrypt the DATA and returns a TequelCrypt 
    pub fn teq_encrypt(&mut self, data: &str, key: &str) -> TequelEncryption {

        let ka = key.as_bytes();
        let kb = self.rand_mini().as_bytes().to_vec();
        let kc = 0x102912fau32.to_be_bytes();

        let mut mixmac = String::new();
        mixmac.push_str(std::str::from_utf8(&ka).unwrap());
        mixmac.push_str(&kb.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&kc.iter().map(|s| format!("{:02x}", s)).collect::<String>());

        let hashmixmac = self.dt_hash(&mixmac);

        let mut buff_res_bytes = Vec::new();

        for (i, &byte) in data.as_bytes().iter().enumerate() {

            let mut c = byte;

            c = c.wrapping_add(ka[i % ka.len()]);
            c = c ^ kb[i % kb.len()];
            c = c.wrapping_add(kc[i % 4]);


            buff_res_bytes.push(c)

        }

        let res = buff_res_bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();


        let saltres = kb.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        
        TequelEncryption { 
            data: res, 
            salt: saltres, 
            key: key.to_string(), 
            mac: hashmixmac, 
        }

    }


    /// ### Tequel Decryption
    /// ```
    /// let tequel : Tequel = Tequel::new();
    /// 
    /// let key: &str = "super_secret_key";
    /// let msg: &str = "hello world";
    /// 
    /// let encrypted: TequelEncryption = tequel.teq_encrypt(&msg, &key);
    /// let decrypted: String = match tequel.teq_decrypt(&encrypted) {
    ///     Ok(d) => d,
    ///     Err(e) => {
    ///         println!("{}", e);
    ///         String::from("ERR")
    ///     }
    /// }
    /// ```
    /// Decrypt a TequelCrypt and returns the DATA decrypted
    pub fn teq_decrypt(&mut self, tequel_crypt: &TequelEncryption) -> Result<String, Box<dyn std::error::Error>> {

        let salt = &tequel_crypt.salt;
        let kb = &tequel_crypt.key.as_bytes();

        let salt = match self.decode_hex(&salt) {
            Ok(s) => s,
            Err(e) => {
                println!("In Salt: {}", e);
                std::process::exit(1)
            }
        };

        let keyc = 0x102912fau32.to_be_bytes();


        let mut mixmac = String::new();
        mixmac.push_str(std::str::from_utf8(&tequel_crypt.key.as_bytes()).unwrap());
        mixmac.push_str(&salt.iter().map(|s| format!("{:02x}", s)).collect::<String>());
        mixmac.push_str(&keyc.iter().map(|s| format!("{:02x}", s)).collect::<String>());

        let hashmixmac = self.dt_hash(&mixmac);

        if hashmixmac != tequel_crypt.mac {
            return Err("ALERT! Hash was modified! MAC not match.".into())
        }


        let hash = &tequel_crypt.data;

        let mut buff_res = Vec::new();

        let hash = match self.decode_hex(&hash) {
            Ok(s) => s,
            Err(e) => {
                return Err(format!("HASH denied: {}", e).into())
            }
        };

        for (i, &byte) in hash.iter().enumerate() {

            let mut c = byte;

            c = c.wrapping_sub(keyc[i % 4]);
            c = c ^ salt[i % salt.len()];
            c = c.wrapping_sub(kb[i % kb.len()]);

            buff_res.push(c)

        }

        

        let res = match String::from_utf8(buff_res) {
            Ok(r) => r,
            Err(e) => {
                println!("{}", e);
                String::new()
            }
        };

        Ok(res)

    }


    fn decode_hex(&self, s: &str) -> Result<Vec<u8>, ParseIntError> {
        if s.len() % 2 != 0 {
            return Err("Hex string has an odd length".parse::<u8>().unwrap_err()); 
        }

        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }

}