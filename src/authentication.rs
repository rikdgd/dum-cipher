use hmac::{Hmac, Mac};
use sha2::Sha256;


type HmacSha256 = Hmac<Sha256>;


/// Generates a HMAC using SHA256.
/// 
/// ## parameters:
/// * `data` - The data which a MAC should be created of.
/// * `key` - The private key that should be used for generating the MAC.
/// 
/// ## returns:
/// * `Some(Vec<u8>)` - When successful, returns a vector with the HMAC bytes.
/// * `None` - When no HMAC could be generated using the private key.
pub fn generate_hmac(data: &[u8], key: &[u8]) -> Option<[u8; 32]> {
    let mut hmac = HmacSha256::new_from_slice(key).ok()?;
    hmac.update(data);
    let res_mac = hmac.finalize();

    let hmac_bytes = res_mac.into_bytes().to_vec();
    
    if hmac_bytes.len() == 32 {
        let mut mac_arr = [0u8; 32];
        for (i, byte) in hmac_bytes.iter().enumerate() {
            mac_arr[i] = byte.clone();
        }
        Some(mac_arr)
        
    } else {
        None
    }
}
