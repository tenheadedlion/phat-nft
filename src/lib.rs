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
    pub fn aes_gcm_encrypt(encryption_key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = Key::from_slice(encryption_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(iv);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| Error::CannotEncrypt)?;
        Ok(ciphertext)
    }

    pub fn aes_gcm_decrypt(encryption_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
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

    use ink_lang as ink;
    use ink_prelude::{string::String, vec::Vec};
    use ink_storage::traits::{PackedLayout, SpreadAllocate, SpreadLayout};
    use ink_storage::Mapping;
    use pink::PinkEnvironment;
    type PropertyId = u128;
    use super::inphat::*;
    use pink::chain_extension::signing;

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
        fn grant_backup_permission(&mut self, acc: AccountId) -> Result<()>;
        #[ink(message)]
        fn export(&self) -> Result<Vec<u8>>;
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
        // todo: allow iteration over this
        // https://github.com/paritytech/substrate/issues/11410
        registered_props: Mapping<PropertyId, Record>,
        // since we can't iterate through the mapping, we use a vector to keep track of all the properties,
        registered_props_shadow: Vec<PropertyId>,
        // people who have permission to export keys
        backup_operators: Vec<AccountId>,
    }

    /// Stores property-related information
    #[derive(
        Encode, Decode, Debug, PartialEq, Eq, Clone, SpreadLayout, PackedLayout, SpreadAllocate,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Record {
        owner: AccountId,
        prop_id: PropertyId,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
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
        fn verify_ownership(&self, _account: AccountId, _prop_id: PropertyId) -> bool {
            // todo!
            true
        }
    }

    impl Backupable for Vault {
        /// Grant permission to an account
        #[ink(message)]
        fn grant_backup_permission(&mut self, acc_id: AccountId) -> Result<()> {
            self.backup_operators.push(acc_id);
            Ok(())
        }

        /// Export all keys into a binary string in substrate encoding,
        ///  for more details check this out: https://docs.substrate.io/reference/scale-codec/
        #[ink(message)]
        fn export(&self) -> Result<Vec<u8>> {
            let caller = Self::env().caller();

            if !self.backup_operators.contains(&caller) {
                return Err(Error::PermissionDenied);
            }

            let mut vec_of_records: Vec<Record> = Vec::new();
            for prop_id in self.registered_props_shadow.iter() {
                let record = self.registered_props.get(prop_id).unwrap();
                vec_of_records.push(record);
            }
            Ok(vec_of_records.encode())
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
        pub fn register_ownership(&mut self, prop_id: PropertyId, acc_id: AccountId) -> Result<()> {
            let caller = Self::env().caller();
            if !self.admins.contains(&caller) {
                return Err(Error::PermissionDenied);
            }

            if !self.registered_props.contains(prop_id) {
                let (private_key, public_key) = Self::derive_key_pair();
                let record = Record {
                    owner: acc_id,
                    prop_id,
                    private_key,
                    public_key,
                };
                self.registered_props.insert(prop_id, &record);
                self.registered_props_shadow.push(prop_id);
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
                self.registered_props_shadow.push(prop_id);
                return Ok(());
            }

            Ok(())
        }

        fn derive_key_pair() -> (Vec<u8>, Vec<u8>) {
            let private_key = signing::derive_sr25519_key("some salt".as_bytes());
            let public_key =
                signing::get_public_key(&private_key, pink::chain_extension::SigType::Sr25519);
            (private_key, public_key)
        }

        /// Derives Encryption key from property meta data
        fn derive_encryption_key(record: &Record) -> Result<(Vec<u8>, Vec<u8>)> {
            // todo: pink-extension should open several API for this
            let key = record.owner.get_pubkey().to_vec();
            let iv: [u8; 12] = key.to_array();
            Ok((key, iv.to_vec()))
        }
    }

    impl PropKeyManagement for Vault {
        /// Derives an encryption key, and an assess key(iv) from property metainfo,
        /// the keys are used for AES-GCM cipher
        ///
        /// # Detail
        ///
        /// The owner of the property is able to aes_gcm_encrypt and aes_gcm_decrypt the content of property using this key;
        /// After transferring the ownership to another person, the formal owner will not be able
        ///     to access the encrypted property.
        ///
        /// To enforce ownership, here is one possible strategy:
        ///     the admins get the encryption key, retrieve the original content,
        ///     and then re-aes_gcm_encrypt the content using another encryption key owned by the new owner.
        ///
        /// This phat contract simply just provides key derivation computering power and access control,
        ///     and does not engage in ownership management
        ///
        /// # Permission
        ///
        /// * contract admins
        /// * the property owner
        ///
        #[ink(message)]
        fn get_encryption_key(&self, prop_id: PropertyId) -> Result<(Vec<u8>, Vec<u8>)> {
            let caller = Self::env().caller();

            let record = self
                .registered_props
                .get(prop_id)
                .map(Ok)
                .unwrap_or(Err(Error::NoSuchProperty))?;
            if record.owner != caller && !self.admins.contains(&caller) {
                return Err(Error::PropertyOwnershipDenied);
            }

            Self::derive_encryption_key(&record)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_lang as ink;
        use openbrush::traits::mock::{Addressable, SharedCallStack};

        fn default_accounts() -> ink_env::test::DefaultAccounts<PinkEnvironment> {
            ink_env::test::default_accounts::<Environment>()
        }

        #[ink::test]
        fn test_key_managerment() {
            pink_extension_runtime::mock_ext::mock_all_ext();

            // an ownership transfer scenario:
            //
            //  1. assume there is a property with id as '1', with content as "the first hello world!"
            //  2. alice owns the property
            //  3. the contract generates an encryption key for alice
            //  4. alice sells that property to bob
            //  5. somehow the contract knows the transfer of ownership and generates an encryption key for bob
            //  6. alice no longer owns the property but she attempts to aes_gcm_decrypt it, she must fail
            //  7. now bob is the property owner, he is able to claim the plaintext of the property

            let prop_id = 1;
            let prop = b"the first hello world!".to_vec();

            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.charlie);

            // the deployer is not an admin
            let contract =
                Addressable::create_native(1, Vault::new(accounts.django), stack.clone());
            assert_eq!(contract.call().deployer, accounts.alice);

            // the admin django tells the contract that alice owns the property
            stack.switch_account(accounts.django).unwrap();
            contract
                .call_mut()
                .register_ownership(prop_id, accounts.alice)
                .unwrap();

            // alice is able to retrieve the encryption key
            stack.switch_account(accounts.alice).unwrap();
            let enc_key_alice = contract.call().get_encryption_key(prop_id).unwrap();

            // alice encrypts the property and stores it somewhere
            let cipher_prop =
                helper::aes_gcm_encrypt(&enc_key_alice.0, &enc_key_alice.1, &prop).unwrap();

            // bob tries to retrieve the encryption key but he must fail
            stack.switch_account(accounts.bob).unwrap();
            let enc_key_bob = contract.call().get_encryption_key(prop_id);
            assert!(enc_key_bob.is_err());

            // bob trades with alice and now owns the property
            // django informs the contract of the transaction
            stack.switch_account(accounts.django).unwrap();

            // the admins supervise the transaction and make sure it is done,
            // they get the key from the contract and retrieve the property
            stack.switch_account(accounts.django).unwrap();
            let key_by_force = contract.call().get_encryption_key(prop_id).unwrap();
            let decrypted_prop =
                helper::aes_gcm_decrypt(&key_by_force.0, &key_by_force.1, &cipher_prop).unwrap();

            // After getting the original content, the admins inform the contract of the ownership change
            _ = contract
                .call_mut()
                .register_ownership(prop_id, accounts.bob);
            let this_key_belongs_to_bob = contract.call().get_encryption_key(prop_id).unwrap();
            let cipher_prop = helper::aes_gcm_encrypt(
                &this_key_belongs_to_bob.0,
                &this_key_belongs_to_bob.1,
                &decrypted_prop,
            )
            .unwrap();

            // now alice is unable to claim the key
            stack.switch_account(accounts.alice).unwrap();
            let enc_key_alice_again = contract.call().get_encryption_key(prop_id);
            assert!(enc_key_alice_again.is_err());

            // and if alice attempts to aes_gcm_decrypt the prop with her old key, she will fail
            assert!(
                helper::aes_gcm_decrypt(&enc_key_alice.0, &enc_key_alice.1, &cipher_prop).is_err()
            );

            // bob gets his key and retrieve the content expectedly
            stack.switch_account(accounts.bob).unwrap();
            let key_bob = contract.call().get_encryption_key(prop_id).unwrap();
            let stuff_decrypted_by_bob =
                helper::aes_gcm_decrypt(&key_bob.0, &key_bob.1, &cipher_prop).unwrap();
            assert_eq!(stuff_decrypted_by_bob, prop);
        }

        #[ink::test]
        fn test_export() {
            pink_extension_runtime::mock_ext::mock_all_ext();
            let prop_id = 1;
            let prop2_id = 2;

            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.charlie);

            let contract =
                Addressable::create_native(1, Vault::new(accounts.django), stack.clone());

            stack.switch_account(accounts.django).unwrap();
            contract
                .call_mut()
                .register_ownership(prop_id, accounts.alice)
                .unwrap();
            contract
                .call_mut()
                .register_ownership(prop2_id, accounts.eve)
                .unwrap();
            
            // register an export operator
            _ = contract.call_mut().grant_backup_permission(accounts.bob);

            // bob issues an exportation
            stack.switch_account(accounts.bob).unwrap();
            let exp = contract.call().export().unwrap();
            let mut exp: &[u8] = &exp;

            type VecRecord = Vec<Record>;
            let rec_replay = VecRecord::decode(&mut exp).ok().unwrap();
            let r0 = &rec_replay[0];
            let r1 = &rec_replay[1];

            assert_eq!(r0.owner, accounts.alice);
            assert_eq!(r0.prop_id, prop_id);
            
            assert_eq!(r1.owner, accounts.eve);
            assert_eq!(r1.prop_id, prop2_id);
        }
    }
}
