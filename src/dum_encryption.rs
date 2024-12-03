use std::io::{ErrorKind, Result as IoResult};
use crate::key_generation::{derive_key_from_passphrase, KeyDetails};
use crate::authentication;


const ROTATE_CHUNK_SIZE: usize = 25;    // 5x5 matrix
const MIRROR_CHUNK_SIZE: usize = 9;     // 3x3 matrix


pub fn encrypt(mut data: Vec<u8>, password: &str) -> IoResult<Vec<u8>> {
    let key_details = derive_key_from_passphrase(password, None);
    let mac = authentication::generate_MAC(&data, &key_details.key).unwrap();
    
    data = xor_data(data, &key_details)?;
    data = {
        // Shuffle the data
        let rotated_data = rotate_data(data, false);
        mirror_data(rotated_data)
    };
    
    // append salt to encrypted data
    for byte in key_details.salt {
        data.push(byte);
    }
    
    // append MAC to encrypted data
    for byte in mac {
        data.push(byte);
    }
    
    Ok(data)
}

pub fn decrypt(mut data: Vec<u8>, password: &str) -> IoResult<Vec<u8>> {
    
    // Get the MAC from last 32 bytes of encrypted data
    let stored_mac = data.split_off(data.len() - 32);
    
    // Get salt from last 16 bytes
    let salt_vec = data.split_off(data.len() - 16);
    let mut salt = [0u8; 16];
    for (i, byte) in salt_vec.iter().enumerate() {
        salt[i] = byte.clone();
    }

    let key_details = derive_key_from_passphrase(password, Some(salt));
    
    
    data = {
        let mirrored_data = mirror_data(data);
        rotate_data(mirrored_data, true)
    };
    data = xor_data(data, &key_details)?;
    
    // recalculate the MAC to verify both are correct. 
    let new_mac = authentication::generate_MAC(&data, &key_details.key).unwrap();
    
    // Check if both MAC's are the same
    for i in 0..32 {
        if stored_mac[i] != new_mac[i] {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "Authentication process failed"
            ));
        }
    }
    
    Ok(data)
}


fn xor_data(data: Vec<u8>, key_details: &KeyDetails) -> IoResult<Vec<u8>> {
    let mut new_data = Vec::new();

    for chunk in data.chunks(key_details.key.len()) {
        let xor_chunk = xor_chunk(chunk, key_details)
            .expect("chunk and key length were not the same");
        for byte in xor_chunk {
            new_data.push(byte);
        }
    }
    
    Ok(new_data)
}

fn rotate_data(data: Vec<u8>, reverse: bool) -> Vec<u8> {
    let mut rotated_data_buffer: Vec<u8> = Vec::new();
    for chunk in data.chunks(ROTATE_CHUNK_SIZE) {
        if chunk.len() == ROTATE_CHUNK_SIZE {
            let chunk: [u8; ROTATE_CHUNK_SIZE] = match chunk.try_into() {
                Ok(arr) => arr,
                Err(_) => panic!("Slice does not have the right amount of elements: {ROTATE_CHUNK_SIZE}"),
            };

            if !reverse {
                if let Some(rotated_data) = rotate_chunk(chunk.into()) {
                    rotated_data_buffer.append(&mut rotated_data.to_vec())
                }
            } else {
                if let Some(rotated_data) = reverse_rotate_chunk(chunk.into()) {
                    rotated_data_buffer.append(&mut rotated_data.to_vec())
                }
            }

        } else {
            rotated_data_buffer.append(&mut chunk.to_vec());
        }
    }
    
    rotated_data_buffer
}

fn mirror_data(data: Vec<u8>) -> Vec<u8> {
    let mut mirrored_data: Vec<u8> = Vec::new();
    for chunk in data.chunks(MIRROR_CHUNK_SIZE) {
        if chunk.len() == MIRROR_CHUNK_SIZE {
            let chunk: [u8; MIRROR_CHUNK_SIZE] = match chunk.try_into() {
                Ok(arr) => arr,
                Err(_) => panic!("Slice does not have the right amount of elements: {MIRROR_CHUNK_SIZE}"),
            };
            let mirrored_chunk = mirror_chunk(chunk);
            mirrored_data.append(&mut mirrored_chunk.to_vec());
        } else {
            mirrored_data.append(&mut chunk.to_vec());
        }
    }

    mirrored_data
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

fn reverse_rotate_chunk(chunk: [u8; ROTATE_CHUNK_SIZE]) -> Option<[u8; ROTATE_CHUNK_SIZE]> {
    let mut rotated_bytes = [0u8; ROTATE_CHUNK_SIZE];
    
    for (index, byte) in chunk.iter().enumerate() {
        let new_index: Option<usize> = match index {
            20 => Some(0),
            15 => Some(1),
            10 => Some(2),
            5 => Some(3),
            0 => Some(4),
            21 => Some(5),
            18 => Some(6),
            17 => Some(7),
            16 => Some(8),
            1 => Some(9),
            22 => Some(10),
            13 => Some(11),
            12 => Some(12),
            11 => Some(13),
            2 => Some(14),
            23 => Some(15),
            8 => Some(16),
            7 => Some(17),
            6 => Some(18),
            3 => Some(19),
            24 => Some(20),
            19 => Some(21),
            14 => Some(22),
            9 => Some(23),
            4 => Some(24),
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

fn mirror_chunk(chunk: [u8; MIRROR_CHUNK_SIZE]) -> [u8; MIRROR_CHUNK_SIZE] {
    let mut mirrored_chunk = [0u8; MIRROR_CHUNK_SIZE];
    
    for (index, byte) in chunk.iter().enumerate() {
        let new_index = match index {
            0 => 2,
            2 => 0,
            3 => 5,
            5 => 3,
            6 => 8,
            8 => 6,
            _ => index
        };
        mirrored_chunk[new_index] = byte.clone();
    }
    mirrored_chunk
}


fn xor_chunk(chunk: &[u8], key_details: &KeyDetails) -> Option<Vec<u8>> {
    let mut result: Vec<u8> = Vec::new();

    for i in 0..chunk.len() {
        let data_byte = chunk.get(i)?;
        let key_byte = key_details.key.get(i)?;

        result.push(data_byte ^ key_byte);
    }

    Some(result)
}


#[cfg(test)]
mod test {
    use crate::dum_encryption;
    use crate::dum_encryption::xor_data;
    use crate::key_generation::{derive_key_from_passphrase};
    use super::ROTATE_CHUNK_SIZE;
    
    #[test]
    fn xor_data_test() {
        let data = b"Hello world!".to_vec();
        let key_details = derive_key_from_passphrase("password", None);
        
        let xored_data = xor_data(data.clone(), &key_details).unwrap();
        let un_xored_data = xor_data(xored_data.clone(), &key_details).unwrap();
        
        assert_eq!(data, un_xored_data);
    }
    
    #[test]
    fn rotate_chunk_test() {
        let data: [u8; ROTATE_CHUNK_SIZE] = b"welcome to my test 123456".to_owned();
        
        let rotated_data = dum_encryption::rotate_chunk(data.clone()).unwrap();
        let reversed_data = dum_encryption::reverse_rotate_chunk(rotated_data.clone()).unwrap();
        
        for i in 0..ROTATE_CHUNK_SIZE {
            assert_eq!(data[i], reversed_data[i]);
        }
    }

    #[test]
    fn dum_e2e_test() {
        let input = b"Lorem ipsum dolor sit amet, consectetur adipiscing".to_vec();
        let password = String::from("password123");

        let encrypted = dum_encryption::encrypt(input.clone(), &password).unwrap();
        let decrypted = dum_encryption::decrypt(encrypted.clone(), &password).unwrap();

        assert_eq!(input, decrypted);
    }
}