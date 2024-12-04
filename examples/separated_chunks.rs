use dum_cipher::dum_encryption;
use dum_cipher::encryption_options::EncryptionOptions;

fn main() -> std::io::Result<()> {
    let pass = "welcome123".to_string();
    let data = b"lorem ipsum of zoiets was het.".to_vec();
    let options = EncryptionOptions {
        separate_chunks: true,
        use_hmac: true,
        xor_data: true,
        shuffle_data: true,
    };
    
    let ciphertext = dum_encryption::encrypt(data.clone(), &pass, Some(options))?;
    println!("ciphertext:\n{}", String::from_utf8_lossy(&ciphertext));
    
    Ok(())
}