use std::io::Result as StdResult;
use crate::key_generation::{derive_key_from_passphrase, KeyDetails};


const ROTATE_CHUNK_SIZE: usize = 25;  // for 5x5 matrix
const MIRROR_CHUNK_SIZE: usize = 9;


pub fn encrypt(data: Vec<u8>, password: String) -> StdResult<Vec<u8>> {
    let key_details = derive_key_from_passphrase(&password, None);
    let mut encrypted_bytes: Vec<u8> = Vec::new();

    for chunk in data.chunks(key_details.key.len()) {
        let xor_chunk = xor_chunk(chunk, &key_details)?;
        for byte in xor_chunk {
            encrypted_bytes.push(byte);
        }
    }
    
    Ok(encrypted_bytes)
}

pub fn decrypt(data: Vec<u8>, password: String, salt: [u8; 16]) -> StdResult<Vec<u8>> {
    let key_details = derive_key_from_passphrase(&password, Some(salt));
    let mut decrypted_bytes = Vec::new();
    
    for chunk in data.chunks(key_details.key.len()) {
        let xor_chunk = xor_chunk(chunk, &key_details)?;
        for byte in xor_chunk {
            decrypted_bytes.push(byte);
        }
    }

    Ok(decrypted_bytes)
}

fn shuffle_data(data: Vec<u8>) -> Vec<u8> {
    
    let mut rotated_data_buffer = Vec::new(); 
    for chunk in data.chunks(ROTATE_CHUNK_SIZE) {
        if chunk.len() == ROTATE_CHUNK_SIZE {
            if let Some(rotated_data) = rotate_chunk(chunk.into()) {
                rotated_data_buffer = rotated_data.to_vec();
            }
        }
    }
    
    let mut mirrored_data = Vec::new();
    for chunk in data.chunks(MIRROR_CHUNK_SIZE) {
        if chunk.len() == MIRROR_CHUNK_SIZE {
            todo!()
        }
    }
    
    todo!()
}

fn rotate_chunk(chunk: [u8; ROTATE_CHUNK_SIZE]) -> Option<[u8; ROTATE_CHUNK_SIZE]> {
    let mut rotated_bytes = [0u8; ROTATE_CHUNK_SIZE];
    
    for (index, byte) in chunk.iter().enumerate() {
        let new_index: Option<usize> = match index {
            0 => Some(20),
            1 => Some(15),
            2 => Some(10),
            3 => Some(5),
            4 => Some(0),
            5 => Some(21),
            6 => Some(18),
            7 => Some(17),
            8 => Some(16),
            9 => Some(1),
            10 => Some(22),
            11 => Some(13),
            12 => Some(12),
            13 => Some(11),
            14 => Some(2),
            15 => Some(23),
            16 => Some(8),
            17 => Some(7),
            18 => Some(6),
            19 => Some(3),
            20 => Some(24),
            21 => Some(19),
            22 => Some(14),
            23 => Some(9),
            24 => Some(4),
            _ => None
        };
        
        if let Some(i) = new_index {
            rotated_bytes[i] = byte.clone();
        } else {
            return None;
        }
    }
    
    Some(rotated_bytes)
}

fn xor_chunk(chunk: &[u8], key_details: &KeyDetails) -> StdResult<Vec<u8>> {
    let mut result: Vec<u8> = Vec::new();

    for i in 0..chunk.len() {
        let data_byte = chunk.get(i).unwrap();
        let key_byte = key_details.key.get(i).unwrap();

        result.push(data_byte ^ key_byte);
    }

    Ok(result)
}