#[derive(Debug, Copy, Clone, PartialEq)]
pub struct EncryptionOptions {
    pub separate_chunks: bool,
    pub use_hmac: bool,
    pub xor_data: bool,
    pub shuffle_data: bool,
}
