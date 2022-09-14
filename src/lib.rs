#![cfg_attr(not(feature = "std"), no_std)]

use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod vault {
    use super::pink;
    use ink_lang as ink;
    use ink_prelude::{
        string::{String, ToString},
        vec::Vec,
    };
    use ink_primitives::Key;
    use ink_storage::traits::{PackedLayout, SpreadAllocate, SpreadLayout, StorageLayout};
    use ink_storage::Mapping;
    use pink::http_get;
    use pink::PinkEnvironment;
    use scale::{Decode, Encode};

    type PropertyId = u128;
    pub type Result<T> = core::result::Result<T, Error>;
    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        PropertyHasAlreadyBeenRegistered,
        NoSuchProperty,
        PropertyOwnershipDenied,
        InvalidPropertySignature,
    }

    #[ink::trait_definition]
    pub trait PropKeyManagement {
        #[ink(message)]
        fn register(&mut self, prop_id: PropertyId) -> Result<()>;
        #[ink(message)]
        fn get_encryption_key(&self, prop_id: PropertyId) -> Result<Vec<u8>>;
    }

    #[ink::trait_definition]
    pub trait SubQuery {
        #[ink(message)]
        fn verify_ownership(&self, claimer: AccountId, prop_id: PropertyId) -> bool;
    }

    #[ink::trait_definition]
    pub trait Backupable {
        #[ink(message)]
        fn export(&self) -> Result<String>;
    }

    /// A secret vault
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Vault {
        name: String,
        admins: Vec<AccountId>,
        registered_props: Mapping<PropertyId, Record>,
    }

    /// Stores user's properties
    #[derive(
        Encode, Decode, Debug, PartialEq, Eq, Clone, SpreadLayout, PackedLayout, SpreadAllocate,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Record {
        owner: AccountId,
        prop_id: PropertyId,
        // we don't recommend transferring property in plaintext,
        // but in fact, the smart contract won't analyze the data,
        // it just takes the data as a sequence of bytes, and saves the data as long as its signature is valid.
        // this field consists of 2 components, the 1st one is the original data, the second is its signature/checksum
        prop_data: Option<(Vec<u8>, Vec<u8>)>,
        // each property item has a corresponding key pair
        keypair: Vec<u8>,
    }

    trait PublickeyOwner {
        fn get_pubkey(&self) -> &[u8];
    }
    impl PublickeyOwner for AccountId {
        fn get_pubkey(&self) -> &[u8] {
            self.as_ref()
        }
    }

    impl SubQuery for Vault {
        #[ink(message)]
        fn verify_ownership(&self, claimer: AccountId, prop_id: PropertyId) -> bool {
            true
        }
    }

    impl Backupable for Vault {
        type Error = self::Error;
        /// Export all keys into a json
        #[ink(message)]
        fn export(&self) -> Result<String> {
            Ok(String::new())
        }
    }

    impl Vault {
        #[ink(constructor)]
        pub fn new() -> Self {
            let admin = Self::env().caller();
            ink_lang::utils::initialize_contract(|this: &mut Self| {})
        }

        /// Verifies if the claimer is actually the owner of the property
        ///
        /// This is achieved by sending requests to indexing services.
        fn verify_ownership(claimer: AccountId, prop_id: PropertyId) -> bool {
            true
        }

        /// Saves the property submitted by the property owner
        ///
        /// To invoke this function, the owner of the property must have registered the property
        ///     by the `register` function.
        ///
        /// todo: should we verify whether the `encrypted_prop` is valid?
        /// if the owner submitted a invalid prop, and after he retrieves the data once again,
        ///  he claims the data is corrupted, this is too bad for a secret-saveing service provider,
        /// we want the user to sign the property using his/her private key;
        /// Upon receipt of the property data, we examinate the signature of the data,
        /// if the signature is OK, we accept the property.
        #[ink(message)]
        pub fn save_property(
            &mut self,
            prop_id: PropertyId,
            encrypted_prop: Vec<u8>,
            encrypted_prop_sig: Vec<u8>,
        ) -> Result<()> {
            // todo: do sth with the boilerplates
            let caller = Self::env().caller();
            let mut record = self
                .registered_props
                .get(prop_id)
                .map(Ok)
                .unwrap_or(Err(Error::NoSuchProperty))?;
            if record.owner != caller {
                return Err(Error::PropertyOwnershipDenied);
            }
            if !self.verify(prop_id, record.owner.get_pubkey(), &encrypted_prop, &encrypted_prop_sig) {
                return Err(Error::InvalidPropertySignature);
            }

            record.prop_data = Some((encrypted_prop, encrypted_prop_sig));
            self.registered_props.insert(prop_id, &record);
            Ok(())
        }

        /// Verifies the the property item submitted by the owner
        ///
        fn verify(&self, prop_id: PropertyId, owner_pubkey: &[u8], encrypted_prop: &[u8], sig: &[u8]) -> bool {
            pink::chain_extension::signing::verify(
                &encrypted_prop,
                owner_pubkey,
                &sig,
                pink::chain_extension::signing::SigType::Sr25519,
            )
        }

        fn derive_key_pair() -> Vec<u8> {
            pink::chain_extension::signing::derive_sr25519_key("some salt".as_bytes())
        }

        fn agree(prop_keypair: &[u8], owner_pubkey: &[u8]) -> Result<Vec<u8>> {
            let mut key = [0u8; 32];
            //key.copy_from_slice()

            Ok(Vec::new())
        }
    }

    impl PropKeyManagement for Vault {
        type Error = self::Error;
        /// Registers property owner
        ///
        /// This function takes the id of the caller as its public key,
        /// generates a key pair for each property item,
        /// and then returns a secret key to the caller for property encryption;
        ///
        #[ink(message)]
        fn register(&mut self, prop_id: PropertyId) -> Result<()> {
            let caller = Self::env().caller();
            if self.registered_props.contains(prop_id) {
                return Err(Error::PropertyHasAlreadyBeenRegistered);
            }
            let keypair = Self::derive_key_pair();
            let record = Record {
                owner: caller,
                prop_id,
                prop_data: None,
                keypair,
            };
            if !self.verify_ownership(caller, prop_id) {
                return Err(Error::PropertyOwnershipDenied);
            }
            self.registered_props.insert(prop_id, &record);
            Ok(())
        }

        /// Derives the encryption key from prop_id
        #[ink(message)]
        fn get_encryption_key(&self, prop_id: PropertyId) -> Result<Vec<u8>> {
            let caller = Self::env().caller();
            let record = self
                .registered_props
                .get(prop_id)
                .map(Ok)
                .unwrap_or(Err(Error::NoSuchProperty))?;
            if record.owner != caller {
                return Err(Error::PropertyOwnershipDenied);
            }
            Self::agree(&record.keypair, record.owner.get_pubkey())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;

        #[ink::test]
        fn test_key_managerment() {}
    }
}
