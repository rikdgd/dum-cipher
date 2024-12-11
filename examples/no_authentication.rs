use dum_cipher::dum_encryption;
use dum_cipher::encryption_options::EncryptionOptions;

fn main() {
    let pass = "welcome123".to_string();
    let data = b"lorem ipsum or something like that.".to_vec();
    let options = EncryptionOptions {
        separate_chunks: false,
        use_hmac: false,
        xor_data: true,
        shuffle_data: true,
    };

    let mut ciphertext = dum_encryption::encrypt(data.clone(), &pass, Some(options))
        .expect("encryption failed");
    println!("ciphertext:\n{}", String::from_utf8_lossy(&ciphertext));

    
    // Slightly adjust ciphertext and try to decrypt: 
    ciphertext[11] = ciphertext[11] + 1; 
    
    let plaintext = dum_encryption::decrypt(ciphertext.clone(), &pass, Some(options)) // adjust password demo
        .expect("decryption failed");
    println!("\ndecrypted data:\n{}", String::from_utf8_lossy(&plaintext));
    
    println!("original data:\n{}", String::from_utf8_lossy(&data));
}