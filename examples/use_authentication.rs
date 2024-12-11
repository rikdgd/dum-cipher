use dum_cipher::dum_encryption;
use dum_cipher::encryption_options::EncryptionOptions;

fn main() {
    let pass = "admin".to_string();
    let data = b"very secret information: Rik uses Comic Sans unironically".to_vec();
    let options = EncryptionOptions {   // We can use all features now!!!
        separate_chunks: false,
        use_hmac: true,
        xor_data: true,
        shuffle_data: true,
    };
    
    let mut ciphertext = dum_encryption::encrypt(data.clone(), &pass, Some(options))
        .expect("data encryption failed");
    println!("ciphertext:\n{}", String::from_utf8_lossy(&ciphertext));
    
    
    // Slightly adjust ciphertext and try to decrypt:
    ciphertext[10] = ciphertext[10] + 1;         // === UN-COMMENT ME ===
    
    let plaintext = dum_encryption::decrypt(ciphertext, &pass, Some(options))
        .expect("data decryption failed");
    println!("\ndecrypted data:\n{}", String::from_utf8_lossy(&plaintext));
}