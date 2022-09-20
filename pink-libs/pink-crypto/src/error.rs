pub use scale::{Decode, Encode};
#[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum CryptoError {
    EcdhInvalidSecretKey,
    EcdhInvalidPublicKey,
    AESCannotEncrypt,
    AESCannotDecrypt
}
