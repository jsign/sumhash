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
//! ```
//! use sumhash::sumhash512;
//! use anyhow::Result;
//!
//! fn main() -> Result<()> {
//!   let mut h = sumhash512::new(None)?;
//!   let bytes_written = h.write("hello world".as_bytes())?;
//!   println!("Bytes written: {}", bytes_written);
//!   let output = h.sum(vec![])?;
//!   println!("Result: {}", hex::encode(&output));
//!
//!   Ok(())
//! }
//! ```
//!
//! [`go-sumhash`]: https://github.com/algorand/go-sumhash
//! [`spec`]: https://github.com/algorand/go-sumhash/blob/master/spec/sumhash-spec.pdf
/// `compress` represents the compression function which is performed on a message.
pub mod compress;
/// `sumhash` is a subset-sum hash.
pub mod sumhash;
/// `sumhash512` is a subset-sum hash variant with an output of is 64 bytes (512 bits).
pub mod sumhash512;
