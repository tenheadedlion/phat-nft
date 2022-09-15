#![cfg_attr(not(feature = "std"), no_std)]

use pink_extension as pink;

mod inphat {
    pub use scale::{Decode, Encode};
    pub type Result<T> = core::result::Result<T, Error>;
    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    // todo: separate the errors
    pub enum Error {
        PropertyHasAlreadyBeenRegistered,
        NoSuchProperty,
        PropertyOwnershipDenied,
        InvalidPropertySignature,
        EmtryProperty,
        PermissionDenied,
        //----------------------
        CannotEncrypt,
        CannotDecrypt,
    }
}

// helper funcions
mod helper {
    use super::inphat::*;
    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    // todo: organize them out to somewhere
    pub trait Roundable<T, const N: usize> {
        fn to_array(&self) -> [T; N];
    }

    impl<T, const N: usize> Roundable<T, N> for Vec<T>
    where
        T: Default + Copy,
    {
        fn to_array(&self) -> [T; N] {
            let mut arr = [T::default(); N];
            for (a, v) in arr.iter_mut().zip(self.iter()) {
                *a = *v;
            }
            arr
        }
    }
    pub fn encrypt(encryption_key: &[u8; 32], iv: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = Key::from_slice(encryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(iv);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| Error::CannotEncrypt)?;
        Ok(ciphertext)
    }

    pub fn decrypt(encryption_key: &[u8; 32], iv: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = Key::from_slice(encryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(iv);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| Error::CannotDecrypt)?;
        Ok(plaintext)
    }
}
#[pink::contract(env=PinkEnvironment)]
mod vault {
    use crate::helper::{self, Roundable};

    use super::pink;
    use ink_env::{AccountId, account_id};
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
    type PropertyId = u128;
    use super::inphat::*;

    #[ink::trait_definition]
    pub trait PropKeyManagement {
        #[ink(message)]
        fn get_encryption_key(&self, prop_id: PropertyId) -> Result<(Vec<u8>, Vec<u8>)>;
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
        // The deployer of this contract is not necessary the admin
        deployer: AccountId,
        admins: Vec<AccountId>,
        registered_props: Mapping<PropertyId, Record>,
    }

    /// Stores user's properties
    /// 
    /// 
    #[derive(
        Encode, Decode, Debug, PartialEq, Eq, Clone, SpreadLayout, PackedLayout, SpreadAllocate,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Record {
        owner: AccountId,
        prop_id: PropertyId,
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
        /// Contructs the contract, and appoints the first admin
        /// 
        /// Note that the person who deploys the contract is not necessarily
        /// in control of the contract;
        /// after construction, the contract is totally in the hands 
        /// of the first admin, who has the power to appoint other admins
        #[ink(constructor)]
        pub fn new(admin: AccountId) -> Self {
            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.deployer = Self::env().caller();
                this.admins.push(admin);
            })
        }

        /// Reports the change of ownship to the contract, associates a property 
        /// to a particular account
        /// 
        /// This function can only be called by the contract adminstrators;
        /// the report must be true, so that the contract will not poll the SubQuery for verification.
        /// in fact, apart from SubQuery, 
        /// this is the other way for the contract to acquire ownership information.
        /// the information is directly from the party that manage the ownership.
        #[ink(message)]
        fn report_ownership(&mut self, prop_id: PropertyId, acc_id: AccountId) -> Result<()> {
            let caller = Self::env().caller();
            if self.admins.contains(caller) {
                return Err(Error::PermissionDenied)
            }

            if !self.registered_props.contains(prop_id) {
                let keypair = Self::derive_key_pair();
                let record = Record {
                    owner: caller,
                    prop_id,
                    keypair,
                };
                return Ok(());
            } 

            let mut record = self
                .registered_props
                .get(prop_id)
                .map(Ok)
                .unwrap_or(Err(Error::NoSuchProperty))?;

            // we observe a transfer in ownership
            if record.owner != acc_id {
                record.owner = acc_id;
                self.registered_props.insert(prop_id, &record);
                return Ok(());
            }

            Ok(())
        }

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
            if !self.verify(
                prop_id,
                record.owner.get_pubkey(),
                &encrypted_prop,
                &encrypted_prop_sig,
            ) {
                return Err(Error::InvalidPropertySignature);
            }

            record.prop_data = Some((encrypted_prop, encrypted_prop_sig));
            self.registered_props.insert(prop_id, &record);
            Ok(())
        }

        fn derive_key_pair() -> Vec<u8> {
            pink::chain_extension::signing::derive_sr25519_key("some salt".as_bytes())
        }

        /// Derives Encryption key from property meta data
        fn derive_encryption_key(record: &Record) -> Result<Vec<u8>> {
            Ok([1; 32].to_vec())
        }
    }

    impl PropKeyManagement for Vault {
        /// Derives the encryption key for a property based on its ownership
        /// 
        /// # Detail
        /// 
        /// The owner of the property is able to encrypt and decrypt the content of property using this key;
        /// After transferring the ownership to another person, the formal owner will not be able
        ///     to access the encrypted property.
        /// 
        /// To enforce ownership, here is one possible strategy:
        ///     the admins get the encryption key, retrieve the original content,
        ///     and then re-encrypt the content using another encryption key owned by the new owner.
        /// 
        /// # Permission
        /// 
        /// * contract admins
        /// * the property owner
        /// 
        #[ink(message)]
        fn get_encryption_key(&self, prop_id: PropertyId) -> Result<Vec<u8>> {
            let caller = Self::env().caller();

            let record = self
                .registered_props
                .get(prop_id)
                .map(Ok)
                .unwrap_or(Err(Error::NoSuchProperty))?;
            
            if record.owner != caller && !self.admins.contains(caller) {
                return Err(Error::PropertyOwnershipDenied);
            }
            
            OK(Self::derive_encryption_key(&record)?)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_env::AccountId;
        use ink_lang as ink;
        use openbrush::traits::mock::{Addressable, SharedCallStack};

        fn default_accounts() -> ink_env::test::DefaultAccounts<ink_env::DefaultEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn test_key_managerment() {
            pink_extension_runtime::mock_ext::mock_all_ext();
            // 1. assume there is a property with id as '1', with content as "the first hello world!"
            // 2. alice owns the property
            // 3. the contract generates an encryption key for alice
            // 4. alice sells that property to bob
            // 5. somehow the contract knows the transfer of ownership and generates an encryption key for bob
            // 6. alice no longer owns the property but she attempts to decrypt it, she must fail
            // 7. now bob is the property owner, he is able to claim the plaintext of the property
            
            
            let prop_id = 1;
            let prop = b"the first hello world!".to_vec();

            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.charlie);
            
            // charlies is the deployer of the contract, but he is not an admin
            let contract = Addressable::create_native(1, contract::new(accounts.django), stack.clone());
            assert_eq!(contract.call().deployer, accounts.charlie);
            
            // the admin django tells the contract that alice owns the property
            stack.switch_account(accounts.django).unwrap();
            contract.report_ownership(prop_id, accounts.alice);

            // alice is able to retrieve the encryption key
            stack.switch_account(accounts.alice).unwrap();
            let enc_key_alice = contract.get_encryption_key(prop_id).unwrap();

            // alice encrypts the property and stores it somewhere
            let cipher_prop = helper::encrypt(enc_key_alice, &prop);
            
            // bob tries to retrieve the encryption key but he must fail
            stack.switch_account(accounts.bob).unwrap();
            let enc_key_bob = contract.get_encryption_key(prop_id);
            assert!(enc_key_bob.is_err());

            // bob trades with alice and now owns the property
            // django informs the contract of the transaction
            stack.switch_account(accounts.django).unwrap();

            // the admins supervise the transaction and make sure it is done,
            // they get the key from the contract and retrieve the property
            stack.switch_account(accounts.django).unwrap();
            let key_by_force = contract.get_encryption_key(prop_id);
            assert!(key_by_force.is_ok());
            let decrypted_prop = helper::decrypt(key_by_force, cipher_prop);

            // After getting the original content, the admins inform the contract of the ownership change
            contract.report_ownership(prop_id, accounts.bob);
            let this_key_belongs_to_bob = contract.get_encryption_key(prop_id).unwrap();
            let cipher_prop = helper::encrypt(this_key_belongs_to_bob, decrypted_prop);

            // now alice is unable to claim the key
            stack.switch_account(accounts.alice).unwrap();
            let enc_key_alice_again = contract.get_encryption_key(prop_id);
            assert!(enc_key_alice_again.is_err());

            // and if alice attempts to decrypt the prop with her old key, she will fail
            assert!(helper::decrypt(enc_key_alice, cipher_prop).is_err());

            // bob gets his key and retrieve the content expectedly
            stack.switch_account(accounts.bob).unwrap();
            let key_bob = contract.get_encryption_key(prop_id).unwrap();
            let stuff_decrypted_by_bob = helper::decrypt(key_bob, cipher_prop).unwrap();
            assert_eq(stuff_decrypted_by_bob, prop);

        }
    }
}
