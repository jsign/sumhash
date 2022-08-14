# sumhash

[![Crates.io](https://img.shields.io/crates/v/sumhash.svg)](https://crates.io/crates/sumhash)
[![Docs.rs](https://docs.rs/sumhash/badge.svg)](https://docs.rs/sumhash)
[![CI](https://github.com/jsign/sumhash/workflows/CI/badge.svg)](https://github.com/jsign/sumhash/actions)

This repository contains a Rust implementation of subset-sum hash function designed by the Algorand project.

The reference implementation is written in Go and can be found in the [`go-sumhash`] repository.
You can also refer to the [`spec`] to see a formal description of the hash function.

This implementation provides a _core_ implementation to be used with the `CoreWrapper` trait. 
If you're interested in an earlier version that was a direct port of the reference implementation, see the `legacyport` branch.

This library has an `AlgorandSumhash512Core` type alias which facilitates a default configuration for Sumhash512Core that utilizes the official seed for the Algorand blockchain state proofs. The AlgorandSumhash512Core uses a lookup table as the default underlying compressor setup instead of a matrix.

This library **is**n't** audited, nor is it an official implementation.

You might be interested in [this article explaining more details](https://ihagopian.com/posts/implementing-algorands-sumhash512-cryptographic-hash-function-in-rust) about the implementation and performance of the library.


[`go-sumhash`]: https://github.com/algorand/go-sumhash
[`spec`]: https://github.com/algorand/go-sumhash/blob/master/spec/sumhash-spec.pdf

## Use

Using the Algorand instance configuration:

```rust
use sumhash::sumhash512core::AlgorandSumhash512Core;
use digest::{core_api::CoreWrapper, FixedOutput, Update};

fn main() {
  let mut h = CoreWrapper::<AlgorandSumhash512Core>::default();
  h.update("hello world".as_bytes());
  let output = h.finalize_fixed();
  println!("Result: {}", hex::encode(&output));
}
```

Generic flavor providing a custom seed:

```rust
use sumhash::sumhash512core::Sumhash512Core;
use digest::{core_api::CoreWrapper, FixedOutput, Update};

fn main() {
  let mut salt = [0; 64];
  salt[0] = 0x13;
  salt[1] = 0x37;
  let mut h = CoreWrapper::from_core(Sumhash512Core::new_with_salt(salt));
  h.update("hello world".as_bytes());
  let output = h.finalize_fixed();
  println!("Result: {}", hex::encode(&output));
}
```

## Cargo

### Build

Run `cargo build`.

### Tests

All the existing tests from `go-sumhash` have been ported and are passing. The tests rely on generating random matrixes using `Shake256` where this library also honors the input and expected exact output match, giving confidence for correctness.

Run `cargo test`:

```bash
running 5 tests
test sumhash512core::test::sumhash512_salt ... ok
test sumhash512core::test::sumhash512 ... ok
test sumhash512core::test::sumhash512_reset ... ok
test sumhash512core::test::test_vector ... ok
test compress::test::compression ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.59s

   Doc-tests sumhash

running 2 tests
test src/lib.rs - (line 37) ... ok
test src/lib.rs - (line 26) ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.21s
```

### Benchmarks

You can run benchmarks with `cargo bench`.

## License

Licensed under either of [MIT license](LICENSE-MIT).

## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md).
