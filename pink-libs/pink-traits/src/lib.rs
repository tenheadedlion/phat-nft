
#![cfg_attr(not(feature = "std"), no_std)]
use core::primitive::str;
use ink_env::AccountId;
use ink_prelude::string::String;
use ink_prelude::string::ToString;
use ink_prelude::vec::Vec;
use scale::{Decode, Encode};

#[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub enum PhatError {
    CodecFailure,
}

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

trait PublickeyOwner {
    fn get_pubkey(&self) -> &[u8];
}

impl PublickeyOwner for AccountId {
    fn get_pubkey(&self) -> &[u8] {
        self.as_ref()
    }
}

/// convert an ascii string as an 256-bit AccountId
///
/// eg.: "111...1111" =>  [1, 1, 1,..., 1, 1, 1]
pub fn from_ascii(src: &str) -> core::result::Result<AccountId, PhatError> {
    assert_eq!(src.len(), 32);
    Ok(AccountId::from(
        src.chars()
            .map(|c| c as u8 - 48u8)
            .collect::<Vec<u8>>()
            .to_array(),
    ))
}

/// convert an account into a literal string
///
/// eg.: [1, 1, ...] => "11..."
pub fn from_accountid<'a>(account: &'a AccountId) -> String {
    let vec = <ink_env::AccountId as AsRef<[u8; 32]>>::as_ref(account)
        .into_iter()
        .map(|n| n + 48)
        .collect::<Vec<u8>>();
    String::from_utf8_lossy(&vec).to_string()
}
