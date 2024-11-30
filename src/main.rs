mod dum_encryption;
mod key_generation;

fn main() -> std::io::Result<()> {
    let message = b"Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!Hello world!".to_vec();
    let password = "welcome123".to_string();
    
    let (encrypted_data, key_details) = dum_encryption::encrypt(message, &password)?;
    let encrypted_message = String::from_utf8_lossy(&encrypted_data);
    println!("encrypted message:\n{encrypted_message}");
    
    let decrypted_data = dum_encryption::decrypt(encrypted_data, &password, key_details.salt)?;
    let decrypted_message = String::from_utf8_lossy(&decrypted_data);
    println!("decrypted message:\n{decrypted_message}");
    
    Ok(())
}
