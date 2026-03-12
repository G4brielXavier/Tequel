
use std::{time::SystemTime};
use getrandom::getrandom;



/// TequelRng is a struct that controls RNG functions. <br><br>
/// As:
/// - `rand_by_nano`
/// - `rand_deep_u32`
/// - `rand_deep_u64`
/// - `rand_lgc`
/// - `rand_in_range_by_deep`
/// - `rand_in_range_by_nano`
pub struct TequelRng {}

impl TequelRng {

    pub fn new() -> Self { Self {  } }



    // RNG by Nano seconds

    /// Generates a set of numbers using **Nano Seconds** + **Constants**
    pub fn rand_by_nano(&self) -> u32{

        let mut state_a: u32 = 0x71374491;
        let mut state_b: u32 = 0x5be0cd19;
        let mut state_c: u32 = 0x5be0cd19;
        let mut state_d: u32 = 0x5be0cd19;

        let now = SystemTime::now();


        if let Ok(dur) = now.duration_since(SystemTime::UNIX_EPOCH) {
            let nanos = dur.subsec_nanos();
            let bytes_nanos = nanos.to_be_bytes();

            for &byte in bytes_nanos.iter() {
                state_a = state_a.wrapping_add(byte as u32);
                state_b = (state_b ^ state_a).rotate_left(13);
                state_c = state_c.wrapping_add(state_b);
                state_d = (state_d ^ state_c).rotate_left(18);
            }

        };
        
        state_d
    }




    // RNG by SO/Hardware

    /// Generates a random `u32` from hardware trash.  
    pub fn rand_deep_u32(&self) -> u32 {

        let mut buffer = [0u8; 4];
        getrandom(&mut buffer).unwrap();

        u32::from_ne_bytes(buffer)
    }

    /// Generates a random `u64` from hardware trash.
    pub fn rand_deep_u64(&self) -> u64 {
        
        let mut buffer = [0u8; 8];

        getrandom(&mut buffer).unwrap();

        u64::from_ne_bytes(buffer)

    }



    // LGC (Linear Congruential Generator)

    /// Generates a random `u32` from a M.A (Modular Arithmetic) with `seed`. 
    pub fn rand_lgc(&self, mut seed: u32) -> u32 {

        let a: u32 = 1201029921;
        let c: u32 = 885949403;
        let m: u32 = 82721712;

        seed = (a.wrapping_mul(seed).wrapping_add(c)) % m;
        seed

    }



    // In range
    
    /// Generates a random `u32` using `rand_deep_u32` between `min` and `max`.
    pub fn rand_in_range_by_deep(&self, min: u32, max: u32) -> u32 {

        let range = max - min + 1;
        let limit = u32::MAX - (u32::MAX % range);

        loop {
            let res = self.rand_deep_u32();
            if res < limit {
                return min + (res % range);
            }
        }

    }

    /// Generates a random `u32` using `rand_by_nano` between `min` and `max`.
    pub fn rand_in_range_by_nano(&self, min: u32, max: u32) -> u32 {

        let range = max - min + 1;
        let limit = u32::MAX - (u32::MAX % range);

        loop {
            let res = self.rand_by_nano();
            if res < limit {
                return min + (res % range);
            }
        }

    }

}