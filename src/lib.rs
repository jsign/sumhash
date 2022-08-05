#![warn(missing_docs)]
//! A Rust implementation of Algorand’s subset-sum hash function.
//!
//! This library is a port of the reference implementation [`go-sumhash`] which
//! implements the [`spec`].
//!
//! There's a tension now on between diverging from the referene implementation (hash.Hash interface)
//! and having an idiomatic Rust API.
//!
//! At least at the API level you might expect changes in further versions which will make it more ergonomic.
//!
//! # Example
//!
//! Without salt:
//! ```
//! use sumhash::sumhash512core::SumhashCore;
//! use digest::{core_api::CoreWrapper, FixedOutput, Update};
//! use anyhow::Result;
//!
//! let mut h = CoreWrapper::<SumhashCore>::default();
//! h.update("hello world".as_bytes());
//! let output = h.finalize_fixed();
//! println!("Result: {}", hex::encode(&output));
//! ```
//!
//! Salted:
//! ```
//! use sumhash::sumhash512core::SumhashCore;
//! use digest::{core_api::CoreWrapper, FixedOutput, Update};
//! use anyhow::Result;
//!
//! let mut salt = [0; 64];
//! salt[0] = 0x13;
//! salt[1] = 0x37;
//! let mut h = CoreWrapper::from_core(SumhashCore::new(Some(salt)));
//! h.update("hello world".as_bytes());
//! let output = h.finalize_fixed();
//! println!("Result: {}", hex::encode(&output));
//! ```

//!
//! [`go-sumhash`]: https://github.com/algorand/go-sumhash
//! [`spec`]: https://github.com/algorand/go-sumhash/blob/master/spec/sumhash-spec.pdf
/// `compress` represents the compression function which is performed on a message.
pub mod compress;
/// sumhash is a subset-sum hash.
pub mod sumhash;
/// sumhash512core is a core implementation for CoreWrapper<..>.
pub mod sumhash512core;
