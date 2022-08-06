#![warn(missing_docs)]
//! A Rust implementation of subset-sum hash function designed by the Algorand project.
//!
//! The reference implementation is written in Go and can be found in the [`go-sumhash`] repository.
//! You can also refer to the [`spec`] to see a formal description of the hash function.
//!
//! This implementation isn't a literal port of the Go repository since the official implementation wouldn't
//! lead to idiomatic Rust. In this library we implement a Sumhash512Core core that can be wrapped with CoreWrapper.
//!
//! This means that Sumhash512Core can fit the existing ecosystem that uses CoreWrapper as the base wrapper struct
//! and interface to calculate hash functions.
//!
//! To have confidence that the implementation is correct, all tests from [`go-sumhash`] where included in the repo.
//! The tests rely on randomness generated with Shake256 using particular seeds that were honored such that we can
//! expect each inputo to have an exact output result with the official implementation.
//!
//! This library has a AlgorandSumhash512Core which facilitates a default configuration for Sumhash512Core that
//! utilizes the official seed for the internal compressor. The AlgorandSumhash512Core uses a lookup table as the
//! default underlying compressor setup instead of a matrix. This leads to better performance but a bigger memory
//! overhead.
//!
//! In case you want to use the generic hashing function, meaning not using the baked in seed in Algorand, you can
//! provide your own seed using Sumhash512Core directly.
//!
//! This library could be extended to provide different block size and compressor matrix dimensions.
//!
//! # Examples
//!
//! Using the Algorand instance configuration:
//! ```
//! use sumhash::sumhash512core::AlgorandSumhash512Core;
//! use digest::{core_api::CoreWrapper, FixedOutput, Update};
//! use anyhow::Result;
//!
//! let mut h = CoreWrapper::<AlgorandSumhash512Core>::default();
//! h.update("hello world".as_bytes());
//! let output = h.finalize_fixed();
//! println!("Result: {}", hex::encode(&output));
//! ```
//!
//! Generic flavor providing your own seed.
//! ```
//! use sumhash::sumhash512core::Sumhash512Core;
//! use digest::{core_api::CoreWrapper, FixedOutput, Update};
//! use anyhow::Result;
//!
//! let mut salt = [0; 64];
//! salt[0] = 0x13;
//! salt[1] = 0x37;
//! let mut h = CoreWrapper::from_core(Sumhash512Core::new_with_salt(salt));
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
