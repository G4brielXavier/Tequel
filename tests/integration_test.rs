use tequel_rs::hash::TequelHash;
use tequel_rs::encrypt::TequelEncrypt;
use tequel_rs::error::TequelError;

#[test]
fn test_dif_hash_is_different_from_string() {

    let mut teqhash = TequelHash::new();

    let hash1 = teqhash.dif_hash_string("dog");
    let hash2 = teqhash.dif_hash_string("dog");


    assert_ne!(hash1, hash2);

}

#[test]
fn test_dif_hash_is_different_from_bytes() {

    let mut teqhash = TequelHash::new();

    let hash1 = teqhash.dif_hash_bytes(b"dog");
    let hash2 = teqhash.dif_hash_bytes(b"dog");


    assert_ne!(hash1, hash2);

}

#[test]
fn test_dif_hash_is_equal_from_string() {

    let mut teqhash = TequelHash::new();

    let hash1 = teqhash.dt_hash_string("dog");
    let hash2 = teqhash.dt_hash_string("dog");


    assert_eq!(hash1, hash2);

}

#[test]
fn test_dif_hash_is_equal_from_bytes() {

    let mut teqhash = TequelHash::new();

    let hash1 = teqhash.dt_hash_bytes(b"dog");
    let hash2 = teqhash.dt_hash_bytes(b"dog");


    assert_eq!(hash1, hash2);

}

#[test]
fn test_if_hash_from_string_with_salt_is_valid() {

    let mut teq_hash = TequelHash::new()
        .with_salt("test")
        .with_iteration(50);

    let my_secret = "secret";
    let hash = teq_hash.dt_hash_string(&my_secret);

    assert!(teq_hash.is_valid_hash_from_string(&hash, &my_secret));// OK!

}

#[test]
fn test_if_hash_from_bytes_with_salt_is_valid() {

    let mut teq_hash = TequelHash::new()
        .with_salt("test")
        .with_iteration(50);

    let my_secret = b"secret";
    let hash = teq_hash.dt_hash_bytes(my_secret);

    assert!(teq_hash.is_valid_hash_from_bytes(&hash, my_secret));// OK!

}





#[test]
fn test_tequel_encrypt_full_cycle() {

    let mut teq_crypt = TequelEncrypt::new()
        .with_iteration(100)
        .with_salt("my_salt");

    let original_data = "My secret message 123";
    let key = "tequel_key";

    let encrypted = teq_crypt.encrypt(original_data.as_bytes(), key)
        .expect("Failed to encrypt");

    let decrypted = teq_crypt.decrypt(&encrypted, key)
        .expect("Failed to decrypt");

    assert_eq!(original_data, decrypted, "The encrypted data not match with original!");

}


#[test]
fn test_tequel_stress_loop_100() {


    let mut teq_crypt = TequelEncrypt::new()
        .with_iteration(100)
        .with_salt("my_salt");

    let key = "ultra_safe_key_123";

    for i in 0..100 {
        // Create a different string in each lap (ex: "Data_0", "Data_1" ...)
        let original_data = format!("Secret_Number_Message_{}", i);
        
        // 1. Encrypt (using bytes from formatted string)
        let encrypted = teq_crypt.encrypt(original_data.as_bytes(), key)
            .expect(&format!("Failed in encrypt loop {}", i));

        // 2. Decrypt
        let decrypted = teq_crypt.decrypt(&encrypted, key)
            .expect(&format!("Failed in decrypt loop {} - Erro de UTF-8?", i));

        // 3. Validação
        assert_eq!(original_data, decrypted, "Integrity error loop {}", i);
    }
    
    println!("🔥 100/100 Loop test done! Tequel is solid.");
}
