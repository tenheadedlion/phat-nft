use crate::error::CryptoError;
use curve25519_dalek::scalar::Scalar;
use ink_prelude::vec::Vec;
#[allow(unused_imports)]
use schnorrkel::keys::{ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey};
#[allow(unused_imports)]
use schnorrkel::{MINI_SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
// this module needs to be more general
use pink_extension::chain_extension::{signing, SigType};
use pink_traits::Roundable;

/// A Key entry can be used for multiple purposes, signing, encrypting, etc.
pub struct PhatKey([u8; 32]);

impl PhatKey {
    pub fn new(salt: &[u8]) -> Self {
        let private_key = signing::derive_sr25519_key(salt.as_ref());
        PhatKey(private_key.to_array())
    }

    pub fn dump(&self) -> Vec<u8> {
        self.private_key()
    }

    pub fn restore_from(private_key: &[u8]) -> Self {
        assert_eq!(private_key.len(), 32);
        // todo: too much conversion?
        PhatKey(private_key.to_vec().to_array())
    }

    pub fn private_key(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn public_key(&self) -> Vec<u8> {
        signing::get_public_key(&self.0, SigType::Sr25519)
    }

    /// Agree on a symmetric key with another party's public key
    pub fn agree(&self, pk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.0;
        let key =
            Scalar::from_canonical_bytes(key).expect("This should never fail with correct seed");
        let public = PublicKey::from_bytes(pk).or(Err(CryptoError::EcdhInvalidPublicKey))?;
        Ok((key * public.as_point()).compress().0.to_vec())
    }
}
