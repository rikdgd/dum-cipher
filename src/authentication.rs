use hmac::{Hmac, Mac};
use sha2::Sha256;


type HmacSha256 = Hmac<Sha256>;


pub fn generate_MAC(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(data);
    let res = mac.finalize();

    let code_bytes = res.into_bytes().to_vec();
    println!("MAC: {:?}", code_bytes);

    Some(code_bytes)
}
