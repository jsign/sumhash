#![warn(missing_docs)]
//! This repository contains a Rust implementation of subset-sum hash function designed by the Algorand project.
//!
//! The reference implementation is written in Go and can be found in the [`go-sumhash`] repository.
//! You can also refer to the [`spec`] to see a formal description of the hash function.
//!
//! This implementation isn't a literal port of the Go repository since the official implementation wouldn't lead to idiomatic Rust. In this library, we implement a Sumhash512Core core that can be wrapped with CoreWrapper. If you're interested in an earlier version which was a direct port of the reference implementation, see the `legacyport` branch.
//!
//! To have confidence that the implementation is correct, all tests from [`go-sumhash`] where included in the repo.
//! The tests rely on randomness generated with Shake256 using particular seeds that were honored such that we can
//! expect each inputo to have an exact output result with the official implementation.
//!
//! This library has a `AlgorandSumhash512Core` type alias which facilitates a default configuration for Sumhash512Core that utilizes the official seed for the Algorand blockchain state proofs.
//!
//! This library **isn't** audited or ready for production use, nor is it an official implementation.
//!
//! [`go-sumhash`]: https://github.com/algorand/go-sumhash
//! [`spec`]: https://github.com/algorand/go-sumhash/blob/master/spec/sumhash-spec.pdf
//!
//! # Examples
//!
//! Using the Algorand instance configuration:
//! ```
//! use sumhash::sumhash512core::AlgorandSumhash512Core;
//! use digest::{core_api::CoreWrapper, FixedOutput, Update};
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
/// compress represents the compression function which is performed on a message.
pub mod compress;
/// sumhash512core is a sumhash core implementation for 512 bit output.
pub mod sumhash512core;
