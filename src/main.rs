mod dum_encryption;
mod key_generation;
mod dum_file_encryptor;
mod authentication;
mod encryption_options;

use std::env;
use std::path::Path;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid arguments provided"
        ));
    }
    
    let action = String::from(&args[1]);
    let action = action.as_str();
    let file_path = Path::new(&args[2]);
    let password = String::from(&args[3]);
    
    let encryptor = dum_file_encryptor::DumFileEncryptor::new(file_path)?;
    match action {
        "encrypt" => encryptor.encrypt_file(&password)?,
        "decrypt" => encryptor.decrypt_file(&password)?,
        _ => panic!("Could not understand requested action"),
    }
    
    Ok(())
}
