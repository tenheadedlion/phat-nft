use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use crate::error::CryptoError;
use ink_prelude::vec::Vec;

pub fn aes_gcm_encrypt(encryption_key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::AESCannotEncrypt)?;
    Ok(ciphertext)
}

pub fn aes_gcm_decrypt(encryption_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::AESCannotDecrypt)?;
    Ok(plaintext)
}
