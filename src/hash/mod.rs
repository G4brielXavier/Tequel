use std::str::from_utf8;

/// TequelHash is a struct that controls Hashing, it has `Constants`, `Salt` and `Custom Iterations`. <br><br>
/// Your functions are:
/// - `dif_hash_string`
/// - `dt_hash_string`
/// - `dif_hash_bytes`
/// - `dt_hash_bytes`
/// - `is_valid_hash_from_string`
/// - `is_valid_hash_from_bytes`
pub struct TequelHash {
    pub states: [u32; 10],
    pub salt: String,
    pub iterations: u32
}

impl TequelHash {

    pub fn new() -> Self { 
        Self {
            states: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
                0x428a2f98, 0x71374491
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


    // from &str 
    /// <br>
    /// 
    /// ```
    /// let tequelHash: TequelHash = TequelHash::new();
    /// 
    /// let hash: String = tequelHash.dif_hash_string("my_secret"); // -> s2ohs192...
    /// let hash1: String = tequelHash.dif_hash_string("my_secret"); // -> 29js19ss...
    /// ```
    /// Generates a different HASH even `&str` being same.
    pub fn dif_hash_string(&mut self, input: &str) -> String {

        let combined = format!("{}{}", self.salt, input);

        let byteinput: &[u8] = combined.as_bytes();

        for byte in byteinput.iter() {
            self.states[0] = self.states[0].wrapping_add(*byte as u32);

            for i in 0..9 {
                self.states[i + 1] = (self.states[i + 1] ^ self.states[i]).rotate_left(self.iterations - 7)
            }

            self.states[0] = (self.states[0] ^ self.states[9]).rotate_left(self.iterations + 13);
        }

        for _ in 0..16 {
            for i in 0..9 {
                self.states[i] = (self.states[i + 1] ^ self.states[i]).rotate_left(self.iterations - 17);
            }
        }

        self.states.iter().map(|s| format!("{:08x}", s)).collect::<String>()

    }

    /// <br>
    /// 
    /// ```
    /// let tequelHash: TequelHash = TequelHash::new();
    /// 
    /// let hash: String = tequelHash.dt_hash_string("my_secret"); // -> 9as12sk21...
    /// let hash1: String = tequelHash.dt_hash_string("my_secret"); // -> 9as12sk21...
    /// ```
    /// Generates a unique HASH from the same `&str`.
    pub fn dt_hash_string(&mut self, input: &str) -> String {

        self.states = Self::new().states;

        let combined = format!("{}{}", self.salt, input);

        let byteinput: &[u8] = combined.as_bytes();

        for byte in byteinput.iter() {
            self.states[0] = self.states[0].wrapping_add(*byte as u32);

            for i in 0..9 {
                self.states[i] = (self.states[i + 1] ^ self.states[i]).rotate_left(self.iterations - 7);
            }

            self.states[0] = (self.states[0] ^ self.states[9]).rotate_left(self.iterations + 13)
        }

        for _ in 0..16 {
            for i in 0..9 {
                self.states[i] = (self.states[i + 1] ^ self.states[i]).rotate_left(self.iterations + 13);
            }
        }

        self.states.iter().map(|s| format!("{:08x}", s)).collect::<String>()

    }




    // from &[u8]

    /// <br>
    /// 
    /// ```
    /// let tequelHash: TequelHash = TequelHash::new();
    /// 
    /// let mybytes: &[u8] = b"secret";
    /// 
    /// let hash: String = tequelHash.dif_hash_bytes(&mybytes); // -> 9as12sk21...
    /// let hash1: String = tequelHash.dif_hash_bytes(&mybytes); // -> 29js19ss...
    /// ```
    /// Generates a different HASH even `&[u8]` being same
    pub fn dif_hash_bytes(&mut self, input: &[u8]) -> String {

        let combined = format!("{}{}", self.salt, from_utf8(input).unwrap());

        let byteinput: &[u8] = combined.as_bytes();

        for byte in byteinput.iter() {

            self.states[0] = self.states[0].wrapping_add(*byte as u32);

            for i in 0..9 {
                self.states[i + 1] = (self.states[i + 1] ^ self.states[i]).rotate_left(self.iterations - 7);
            }

            self.states[0] = (self.states[0] ^ self.states[9]).rotate_left(self.iterations + 13);

        }

        for _ in 0..16 {
            for i in 0..9 {
                self.states[i] = (self.states[i + 1] ^ self.states[i]).rotate_left(self.iterations + 17);
            }
        }

        self.states.iter().map(|s| format!("{:08x}", s)).collect::<String>()

    }



    /// <br>
    /// 
    /// ```
    /// let tequelHash: TequelHash = TequelHash::new();
    /// 
    /// let mybytes: &[u8] = b"secret";
    /// 
    /// let hash: String = tequelHash.dt_hash_bytes(&mybytes); // -> 9as12sk21...
    /// let hash1: String = tequelHash.dt_hash_bytes(&mybytes); // -> 9as12sk21...
    /// ```
    /// Generates a unique HASH for the same `&[u8]`.
    pub fn dt_hash_bytes(&mut self, input: &[u8]) -> String {

        self.states = Self::new().states;

        let combined = format!("{}{}", self.salt, from_utf8(input).unwrap());

        let byteinput: &[u8] = combined.as_bytes();

        for byte in byteinput.iter() {

            self.states[0] = self.states[0].wrapping_add(*byte as u32);

            for i in 0..9 {
                self.states[i + 1] = (self.states[i + 1] ^ self.states[i]).rotate_left(self.iterations - 7);
            }

            self.states[0] = (self.states[0] ^ self.states[9]).rotate_left(self.iterations + 13);

        }

        for _ in 0..16 {
            for i in 0..9 {
                self.states[i] = (self.states[i + 1] ^ self.states[i]).rotate_left(self.iterations + 17);
            }
        }

        self.states.iter().map(|s| format!("{:08x}", s)).collect::<String>()

    }


    /// <br>
    /// 
    /// ```
    /// let tequelHash: TequelHash = TequelHash::new();
    /// 
    /// let mybytes: &[u8] = b"secret";
    /// 
    /// let hash: String = tequelHash.dt_hash_bytes(&mybytes); // -> 9as12sk21...
    /// 
    /// if tequelHash.is_valid_hash_from_bytes(&hash, &mybytes) {
    ///     println!("VALID!")
    /// } else {
    ///     println!("NO VALID!")
    /// }
    /// 
    /// ```
    /// Generates a unique HASH for the same `&[u8]`.
    pub fn is_valid_hash_from_bytes(&mut self, hash: &String, value: &[u8]) -> bool {
        
        let mut prop_tequel = TequelHash::new()
            .with_salt(&self.salt)
            .with_iteration(self.iterations);

        if *hash == prop_tequel.dt_hash_bytes(&value) {
            true
        } else {
            false
        }

    }


    /// <br>
    /// 
    /// ```
    /// let tequelHash: TequelHash = TequelHash::new();
    /// 
    /// let my_data: &str = "secret";
    /// 
    /// let hash: String = tequelHash.dt_hash_string(my_data); // -> 9as12sk21...
    /// 
    /// if tequelHash.is_valid_hash_from_string(&hash, &my_data) {
    ///     println!("VALID!")
    /// } else {
    ///     println!("NO VALID!")
    /// }
    /// 
    /// ```
    /// Generates a unique HASH for the same `&[u8]`.
    pub fn is_valid_hash_from_string(&mut self, hash: &String, value: &str) -> bool {
        
        let mut prop_tequel = TequelHash::new()
            .with_salt(&self.salt)
            .with_iteration(self.iterations);

        if *hash == prop_tequel.dt_hash_string(&value) {
            true
        } else {
            false
        }
        
    }


}