#![cfg_attr(not(feature = "std"), no_std)]

pub mod error;
pub mod public_key;
mod aes_gcm;

pub use crate::aes_gcm::*;