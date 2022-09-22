#![cfg_attr(not(feature = "std"), no_std)]

use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod nft_manager {

    use super::pink;

    use ink_lang as ink;
    use ink_prelude::{string::String, string::ToString, vec::Vec};
    use ink_storage::traits::{PackedLayout, SpreadAllocate, SpreadLayout};
    use pink::{http_get, PinkEnvironment};
    type NFTId = u128;

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
        HttpRequestFailed,
        InvalidHTTPResponse,
    }

    #[ink::trait_definition]
    pub trait PropKeyManagement {
        #[ink(message)]
        fn get_encryption_key(&self, nft_id: NFTId) -> Result<Vec<u8>>;
    }

    #[ink::trait_definition]
    pub trait Fetcher {
        #[ink(message)]
        fn set_indexer(&mut self, sq_url: String) -> Result<()>;
        #[ink(message)]
        fn fetch_ownership(&self, nft_id: NFTId) -> Result<AccountId>;
    }

    #[ink::trait_definition]
    pub trait Backupable {
        #[ink(message)]
        fn grant_backup_permission(&mut self, acc: AccountId) -> Result<()>;
        #[ink(message)]
        fn export(&self, nft_id: NFTId) -> Result<Vec<u8>>;
    }

    /// A secret nft_manager
    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct NFTManager {
        name: String,
        // The deployer of this contract is not necessary the admin
        deployer: AccountId,
        admins: Vec<AccountId>,
        // people who have permission to export keys
        backup_operators: Vec<AccountId>,
        // indexing service url: where we know who does an nft belong to
        indexer: String,
        contract_key: Vec<u8>,
    }

    /// Stores nft-related information
    #[derive(
        Encode, Decode, Debug, PartialEq, Eq, Clone, SpreadLayout, PackedLayout, SpreadAllocate,
    )]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Record {
        nft_id: NFTId,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        encryption_key: Vec<u8>,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    pub struct Response<'a> {
        #[serde(borrow)]
        data: Data<'a>,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct Data<'a> {
        #[serde(borrow)]
        nft: Property<'a>,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct Property<'a> {
        owner: &'a str,
    }

    impl Fetcher for NFTManager {
        #[ink(message)]
        fn set_indexer(&mut self, indexer: String) -> Result<()> {
            let caller = Self::env().caller();
            if !self.admins.contains(&caller) {
                return Err(Error::PermissionDenied);
            }
            self.indexer = indexer;
            Ok(())
        }
        /// Requests the indexer for information about nft's owner
        ///
        /// This is where implementations diverge, in this use case,
        /// we assume the indexers can recogize POST data with **graphql** syntax, for example:
        ///     '{"query":"{ nft( id:\"123343\"  ) { owner  }}"}',
        ///
        /// when we use `curl` with POST method and payload like this:
        ///
        /// ```shell
        ///  $ curl 'https://indexer.hello.com/' -H 'Content-Type: application/json' \
        ///     -H 'Accept: application/json' --data-binary
        ///     '{"query":"{ nft( id:\"123343\"  ) { owner  }}"}'
        /// ```
        ///
        /// we get
        ///
        ///     {"data":{"nft":{"owner":"11111111111111111111111111111111"}}}
        ///
        /// This function returns the address of the nft owner
        /// todo: can we abstract this function away?
        #[ink(message)]
        fn fetch_ownership(&self, _prop_id: NFTId) -> Result<AccountId> {
            let resposne = http_get!(&self.indexer);
            if resposne.status_code != 200 {
                return Err(Error::HttpRequestFailed);
            }
            let body = resposne.body;
            let (res, _): (Response, usize) =
                serde_json_core::from_slice(&body).or(Err(Error::InvalidHTTPResponse))?;
            // todo
            Ok(pink_traits::from_ascii(res.data.nft.owner).unwrap())
        }
    }

    impl Backupable for NFTManager {
        /// Grant permission to an account
        #[ink(message)]
        fn grant_backup_permission(&mut self, acc_id: AccountId) -> Result<()> {
            self.backup_operators.push(acc_id);
            Ok(())
        }

        /// Export all keys into a binary string in substrate encoding,
        ///  for more details check this out: https://docs.substrate.io/reference/scale-codec/
        #[ink(message)]
        fn export(&self, nft_id: NFTId) -> Result<Vec<u8>> {
            let caller = Self::env().caller();

            if !self.backup_operators.contains(&caller) {
                return Err(Error::PermissionDenied);
            }

            let prop_key = Self::derive_key_pair(nft_id);
            let private_key = prop_key.private_key();
            let public_key = prop_key.public_key();
            let encryption_key = pink_crypto::public_key::PhatKey::restore_from(&self.contract_key)
                .agree(&public_key)
                .unwrap();

            let record = Record {
                nft_id,
                private_key,
                public_key,
                encryption_key,
            };

            Ok(record.encode())
        }
    }

    impl NFTManager {
        /// Contructs the contract, and appoints the first admin
        ///
        /// Note that the person who deploys the contract is not necessarily
        /// in control of the contract;
        /// after construction, the contract is totally in the hands
        /// of the first admin, who has the power to appoint other admins
        #[ink(constructor)]
        pub fn new(admin: AccountId) -> Self {
            let salt = Self::env().caller();
            let private_key = pink_crypto::public_key::PhatKey::new(salt.as_ref()).dump();
            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.deployer = Self::env().caller();
                this.admins.push(admin);
                this.contract_key = private_key;
            })
        }

        /// Yields a Phatkey
        fn derive_key_pair(nft_id: NFTId) -> pink_crypto::public_key::PhatKey {
            // given the same salt, the following call returns the same result
            pink_crypto::public_key::PhatKey::new(nft_id.to_string().as_bytes())
        }
    }

    impl PropKeyManagement for NFTManager {
        /// Derives an encryption key, and an assess key(iv) from nft metainfo,
        /// these keys are used for AES-GCM cipher
        ///
        /// # Detail
        ///
        /// The owner of the nft is able to encrypt and decrypt the content of nft using this key;
        /// After handing over the ownership to another person, the formal owner will not be able
        ///     to decrypt the encrypted nft.
        ///
        /// To enforce ownership transfer, here is one possible strategy for the party that uses this phat contract:
        ///     the admins get the encryption key, retrieve the original content,
        ///     and then re-encrypt the content using another encryption key owned by the new owner.
        ///
        /// This phat contract is meant to provide key derivation computering power and access control,
        ///     it holds the keys, but it does not use them, therefore it does not check on user data,
        ///     besides, it doesn't know where the users store the properties.
        ///
        /// # Permission
        ///
        /// * contract admins
        /// * the nft owner
        ///
        #[ink(message)]
        fn get_encryption_key(&self, nft_id: NFTId) -> Result<Vec<u8>> {
            let caller = Self::env().caller();
            let owner = self.fetch_ownership(nft_id)?;

            // the admins can bypass the permission checking
            if owner != caller && !self.admins.contains(&caller) {
                return Err(Error::PropertyOwnershipDenied);
            }
            let prop_key = Self::derive_key_pair(nft_id);
            let encryption_key = pink_crypto::public_key::PhatKey::restore_from(&self.contract_key)
                .agree(&prop_key.public_key())
                .unwrap();

            Ok(encryption_key)
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

        macro_rules! mock_http_request {
            ($account: expr) => {
                mock::mock_http_request(move |_| {
                    let response = Response {
                        data: Data {
                            nft: Property {
                                owner: &pink_traits::from_accountid(&$account),
                            },
                        },
                    };
                    let serialized = serde_json::to_string(&response).unwrap();
                    HttpResponse::ok(serialized.as_bytes().to_vec())
                });
            };
        }

        #[ink::test]
        fn test_key_managerment() {
            use pink_extension::chain_extension::{mock, HttpResponse};
            pink_extension_runtime::mock_ext::mock_all_ext();

            // an ownership transfer scenario:
            //
            //  1. assume there is a nft with id as '1', with content as "the first hello world!"
            //  2. alice owns the nft
            //  3. the contract generates an encryption key for alice
            //  4. alice sells that nft to bob
            //  5. somehow the contract knows the transfer of ownership and generates an encryption key for bob
            //  6. alice no longer owns the nft but she attempts to aes_gcm_decrypt it, she must fail
            //  7. now bob is the nft owner, he is able to claim the plaintext of the nft

            let nft_id = 1;
            let prop = b"the first hello world!".to_vec();

            //  12 bytes initialization vector
            let alice_assess_key = b"123456789123";
            let bob_assess_key = b"123456789124";

            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.charlie);

            // the deployer is not an admin
            let contract =
                Addressable::create_native(1, NFTManager::new(accounts.django), stack.clone());
            assert_eq!(contract.call().deployer, accounts.alice);

            // the admin django tells the contract that alice owns the nft
            stack.switch_account(accounts.django).unwrap();

            // alice is able to retrieve the encryption key
            stack.switch_account(accounts.alice).unwrap();

            // mock the response for the http request emitted by `get_encryption_key`,
            // from this response the contract knows the nft now belongs to alice;
            // todo: we are going to work on the subquery response scheme later
            mock_http_request!(accounts.alice);

            let enc_key_alice = contract.call().get_encryption_key(nft_id).unwrap();

            // alice encrypts the nft and stores it somewhere
            let cipher_prop =
                pink_crypto::aes_gcm_encrypt(&enc_key_alice, alice_assess_key, &prop).unwrap();

            // bob tries to retrieve the encryption key but he must fail
            stack.switch_account(accounts.bob).unwrap();
            let enc_key_bob = contract.call().get_encryption_key(nft_id);
            assert!(enc_key_bob.is_err());

            // bob trades with alice and now owns the nft
            // django informs the contract of the transaction
            stack.switch_account(accounts.django).unwrap();

            // the admins supervise the transaction and make sure it is done,
            // they get the key from the contract and retrieve the nft
            stack.switch_account(accounts.django).unwrap();
            let key_by_force = contract.call().get_encryption_key(nft_id).unwrap();
            let decrypted_prop =
                pink_crypto::aes_gcm_decrypt(&key_by_force, alice_assess_key, &cipher_prop)
                    .unwrap();

            // now the nft belongs to bob
            mock_http_request!(accounts.bob);

            let this_key_belongs_to_bob = contract.call().get_encryption_key(nft_id).unwrap();
            let cipher_prop = pink_crypto::aes_gcm_encrypt(
                &this_key_belongs_to_bob,
                bob_assess_key,
                &decrypted_prop,
            )
            .unwrap();

            // now alice is unable to claim the key
            stack.switch_account(accounts.alice).unwrap();
            let enc_key_alice_again = contract.call().get_encryption_key(nft_id);
            assert!(enc_key_alice_again.is_err());

            // and if alice attempts to aes_gcm_decrypt the prop with her old key, she will fail
            assert!(
                pink_crypto::aes_gcm_decrypt(&enc_key_alice, alice_assess_key, &cipher_prop)
                    .is_err()
            );

            // bob gets his key and retrieve the content as expected
            stack.switch_account(accounts.bob).unwrap();
            let key_bob = contract.call().get_encryption_key(nft_id).unwrap();
            let stuff_decrypted_by_bob =
                pink_crypto::aes_gcm_decrypt(&key_bob, bob_assess_key, &cipher_prop).unwrap();
            assert_eq!(stuff_decrypted_by_bob, prop);
        }

        #[ink::test]
        fn test_export() {
            pink_extension_runtime::mock_ext::mock_all_ext();
            let nft_id = 1;

            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.charlie);

            let contract =
                Addressable::create_native(1, NFTManager::new(accounts.django), stack.clone());

            stack.switch_account(accounts.django).unwrap();

            // register an export operator
            _ = contract.call_mut().grant_backup_permission(accounts.bob);

            // bob issues an exportation
            stack.switch_account(accounts.bob).unwrap();
            let exp = contract.call().export(nft_id).unwrap();
            let mut exp: &[u8] = &exp;

            let rec_replay = Record::decode(&mut exp).ok().unwrap();
            let r0 = &rec_replay;

            // todo: further tests on the keys
            assert_eq!(r0.nft_id, nft_id);
        }

        #[ink::test]
        fn test_indexer() {
            use pink_extension::chain_extension::{mock, HttpResponse};
            pink_extension_runtime::mock_ext::mock_all_ext();

            let accounts = default_accounts();
            let stack = SharedCallStack::new(accounts.charlie);

            let contract =
                Addressable::create_native(1, NFTManager::new(accounts.django), stack.clone());
            assert_eq!(contract.call().deployer, accounts.alice);

            mock_http_request!(accounts.django);
            let account = contract.call().fetch_ownership(1).unwrap();
            assert_eq!(accounts.django, account);
        }
    }
}
