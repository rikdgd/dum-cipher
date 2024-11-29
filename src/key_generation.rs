use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;


const ITERATIONS: u32 = 600_000;

#[derive(Debug, Clone, PartialEq)]
pub struct KeyDetails {
    pub password: String,
    pub key: [u8; 32],
    pub salt: [u8; 16],
}

/// Use PBKDF2 to generate a key based on a password
/// 
/// ## parameters:
/// * `password` - The password to use to generate a key.
/// * `salt` - The salt to use when generating the key, will be automatically generated when `None`.
pub fn derive_key_from_passphrase(password: &str, salt: Option<[u8; 16]>) -> KeyDetails {
    let pass = password.as_bytes();
    let salt = if let Some(salt) = salt {
        salt
    } else {
        generate_salt()
    };
    
    let mut key_buffer = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pass, &salt, ITERATIONS, &mut key_buffer);

    KeyDetails {
        password: String::from(password),
        key: key_buffer,
        salt,
    }
}

fn generate_salt() -> [u8; 16] {
    let mut buffer = [0u8; 16];
    rand::thread_rng().fill(&mut buffer);
    buffer
}


