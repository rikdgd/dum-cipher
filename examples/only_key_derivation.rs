use dum_cipher::dum_encryption;
use dum_cipher::encryption_options::EncryptionOptions;

fn main() {
    let pass = "welcome123".to_string();
    let data = b"lorem ipsum of zoiets was het.".to_vec();
    let options = EncryptionOptions {
        separate_chunks: false,
        use_hmac: false,
        xor_data: true,         // without xor_data, key derivation cannot even get used.
        shuffle_data: false,
    };

    let mut ciphertext = dum_encryption::encrypt(data.clone(), &pass, Some(options))
        .expect("encryption failed");
    println!("ciphertext:\n{}", String::from_utf8_lossy(&ciphertext));
    
    
    
    // Slightly adjust ciphertext and try to decrypt: 
    
    // ciphertext[10] = ciphertext[10] + 1; 
    // 
    // let plaintext = dum_encryption::decrypt(ciphertext, &pass, Some(options))
    //     .expect("decryption failed");
    // println!("\ndecrypted data:\n{}", String::from_utf8_lossy(&plaintext));
}