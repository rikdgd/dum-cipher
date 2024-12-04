use std::fs::OpenOptions;
use std::path::Path;
use std::io::{Read, Result as IoResult, Write};
use std::io::Error as IoError;
use std::io::ErrorKind;
use crate::dum_encryption;

#[derive(Debug, Clone, PartialEq)]
pub struct DumFileEncryptor<'a> {
    file_path: &'a Path,
}

impl<'a> DumFileEncryptor<'a> {
    pub fn new(path: &'a Path) -> IoResult<Self> {
        if path.is_file() {
            Ok(Self {
                file_path: path,
            })
        } else {
            Err(IoError::new(
                ErrorKind::NotFound, 
                "The given path does not correspond to a file"
            ))
        }
    }
    
    pub fn encrypt_file(&self, password: &str) -> IoResult<()> {
        let file_bytes = self.get_file_bytes()?;
        let ciphertext = dum_encryption::encrypt(file_bytes, password, None)?;
        
        self.write_bytes_to_file(&ciphertext)?;
        
        Ok(())
    }
    
    pub fn decrypt_file(&self, password: &str) -> IoResult<()> {
        let file_bytes = self.get_file_bytes()?;
        let plaintext = dum_encryption::decrypt(file_bytes, password, None)?;

        self.write_bytes_to_file(&plaintext)?;

        Ok(())
    }
    
    fn get_file_bytes(&self) -> IoResult<Vec<u8>> {
        let mut content_buffer = Vec::new();
        let mut file = OpenOptions::new()
            .read(true)
            .open(self.file_path)?;
        
        file.read_to_end(&mut content_buffer)?;
        file.flush()?;
        
        Ok(content_buffer)
    }
    
    
    /// Clears the files content and then writes the given content to it.
    /// 
    /// ## parameters:
    /// * `bytes` - The bytes that will be written to the file.
    fn write_bytes_to_file(&self, bytes: &[u8]) -> IoResult<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .open(self.file_path)?;
        
        file.set_len(0)?;
        file.write_all(bytes)?;
        file.flush()?;
        
        Ok(())
    }
}
