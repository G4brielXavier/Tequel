use std::collections::HashSet;
use tequel_rs::hash::TequelHash;
use tequel_rs::encrypt::TequelEncrypt;
use std::time::Instant;



#[test]
fn test_dif_hash_is_equal_from_bytes() {

    let mut teqhash = TequelHash::new();

    let hash1 = teqhash.tqlhash(b"dog");
    let hash2 = teqhash.tqlhash(b"dog");


    assert_eq!(hash1, hash2);

}

#[test]
fn test_if_hash_from_bytes_with_salt_is_valid() {

    let mut teq_hash = TequelHash::new()
        .with_salt("test")
        .with_iteration(50);

    let my_secret = b"secret";
    let hash = teq_hash.tqlhash(my_secret);

    assert!(teq_hash.isv_tqlhash(&hash, my_secret));// OK!

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

#[test]
fn test_tequel_stress_loop_10000() {


    let mut teq_crypt = TequelEncrypt::new()
        .with_iteration(100)
        .with_salt("my_salt");

    let key = "ultra_safe_key_123";

    for i in 0..10000 {
        // Create a different string in each lap (ex: "Data_0", "Data_1" ...)
        let original_data = format!("Secret_{}_Message_💀_#{}", i, i * 2);
        
        // 1. Encrypt (using bytes from formatted string)
        let encrypted = teq_crypt.encrypt(original_data.as_bytes(), key)
            .expect(&format!("Failed in encrypt loop {}", i));

        // 2. Decrypt
        let decrypted = teq_crypt.decrypt(&encrypted, key)
            .expect(&format!("Failed in decrypt loop {} - Erro de UTF-8?", i));

        // 3. Validação
        assert_eq!(original_data, decrypted, "Integrity error loop {}", i);
    }
    
    println!("🔥 10000/10000 Loop test done! Tequel is solid.");
}




#[test]
fn test_tequel_fuzzing_resistance() -> Result<(), Box<dyn std::error::Error>> {

    let mut teq = TequelEncrypt::new();

    let as_big = "A".repeat(10000);

    let crazy_inputs = vec![
        "",                     // Empty
        " ",                    // Space
        "\0\0\0",               // Null bytes
        "💀🚀🔥",               // Emojis (Multi-byte UTF-8)
        &as_big,      // large string
        "你好",                 // Mandarim
    ];


    for input in &crazy_inputs {

        let legit_encrypted = teq.encrypt(input.as_bytes(), "key123").map_err(|e| {
            e
        })?;

        let mut corrupted = legit_encrypted.clone();
        corrupted.mac = "ffffffffffffffffffffffffffffffff".to_string(); // false MAC
        corrupted.salt = "00000000".to_string(); // false SALT
        
        let trash_data = teq.decrypt(&corrupted, "key123");

        assert!(trash_data.is_err(), "O Tequel aceitou um objeto corrompido! Erro de integridade.");
        println!("✅ Fuzzing de Objeto: Tequel stopped corromped structure.");

    }

    Ok(())

}



#[test]
fn test_tequel_key_sensitivity() {

    let mut teq = TequelEncrypt::new().with_salt("security_first");
    let original_data = b"Ultra sensible data";

    let real_key = "StrongKey123";
    let fake_key = "StrongKey100";

    let encrypted = teq.encrypt(original_data, real_key).unwrap();

    let result = teq.decrypt(&encrypted, fake_key);

    match result {
        Ok(_) => panic!("Critical Fail: Tequel accepted a wrong key and generate trash"),
        Err(_) => println!("Integrity Security: Key Wrong Blocked")
    }

}


#[test]
fn test_collision_resistance_optimized() {
    // Para 1 bilhão, use um Bloom Filter se tiver a crate, 
    // ou teste lotes menores se quiser usar HashSet sem swap.
    let iterations = 10_000_000; // 100 milhões já é um teste monstro
    let mut seen_hashes = HashSet::with_capacity(iterations);
    let mut collisions = 0;
    let mut hasher = TequelHash::new();
    
    // Buffer reutilizável para evitar format!() e alocações na heap
    let mut buffer = String::with_capacity(64);
    
    println!("🚀 Iniciando teste de colisão: {} iterações", iterations);
    let start = Instant::now();

    for i in 0..iterations {
        buffer.clear();
        // Escreve o ID direto no buffer sem alocar nova String
        use std::fmt::Write;
        write!(&mut buffer, "payload_id_{}", i).unwrap();
        
        let hash = hasher.tqlhash(buffer.as_bytes());

        // Se o hash já existe no set, temos uma colisão
        if !seen_hashes.insert(hash.clone()) {
            collisions += 1;
            println!("💥 COLISÃO ENCONTRADA no índice {}: {}", i, hash);
        }

        // Print de progresso a cada 10 milhões
        if i % 1_000_000 == 0 && i > 0 {
            println!("⏳ {}% concluído...", (i as f32 / iterations as f32) * 100.0);
        }
    }

    let duration = start.elapsed();
    println!("\n✅ Teste Finalizado!");
    println!("📊 Total: {} iterações", iterations);
    println!("💥 Colisões: {}", collisions);
    println!("⏱️ Tempo total: {:.2?}", duration);
    println!("⚡ Velocidade: {:.2} hashes/sec", iterations as f64 / duration.as_secs_f64());

    assert_eq!(collisions, 0, "Tequel falhou no teste de colisão!");
}



#[test]
fn test_tequel_avalanche_string_output() {
    let mut hasher = TequelHash::new();
    let input = b"payload_id_777_supply_chain_data_2026";
    
    // Pegamos o hash base e convertemos de Hex String para Bytes
    let base_hash_hex = hasher.tqlhash(input);
    let base_bytes = hex::decode(&base_hash_hex).expect("Hash base deve ser um hexa válido");
    
    let mut total_bit_flips = 0;
    let total_bits_input = input.len() * 8;

    for byte_idx in 0..input.len() {
        for bit_idx in 0..8 {
            let mut modified_input = input.to_vec();
            modified_input[byte_idx] ^= 1 << bit_idx;
            
            let new_hash_hex = hasher.tqlhash(&modified_input);
            let new_bytes = hex::decode(&new_hash_hex).expect("Novo hash deve ser um hexa válido");
            
            // Comparamos bit a bit entre os arrays de bytes
            for (b1, b2) in base_bytes.iter().zip(new_bytes.iter()) {
                let diff = b1 ^ b2;
                total_bit_flips += diff.count_ones();
            }
        }
    }

    // Calcula a porcentagem baseada no tamanho total do hash (ex: 256 bits ou 64 bits)
    let hash_bits_output = base_bytes.len() * 8; 
    let avalanche_score = (total_bit_flips as f64 / (total_bits_input * hash_bits_output) as f64) * 100.0;

    println!("\n--- 🌪️ RELATÓRIO DE AVALANCHE TEQUEL (STRING OUTPUT) ---");
    println!("📊 Bits totais de saída analisados: {}", total_bits_input * hash_bits_output);
    println!("🎯 Média de Avalanche: {:.2}%", avalanche_score);
    println!("---------------------------------------");

    assert!(avalanche_score > 40.0 && avalanche_score < 60.0);
}