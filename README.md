# sumhash

[![Crates.io](https://img.shields.io/crates/v/sumhash.svg)](https://crates.io/crates/sumhash)
[![Docs.rs](https://docs.rs/sumhash/badge.svg)](https://docs.rs/sumhash)
[![CI](https://github.com/jsign/sumhash/workflows/CI/badge.svg)](https://github.com/jsign/sumhash/actions)

A Rust implementation of Algorand's subset-sum hash function.
This library is following the reference implementation [`go-sumhash`](https://github.com/algorand/go-sumhash
) which implements the [`spec`](https://github.com/algorand/go-sumhash/blob/master/spec/sumhash-spec.pdf
).

This library **isn't** audited or ready for production use, nor is it an official implementation.

## Use

```rust
use sumhash::sumhash512;
use anyhow::Result;

fn main() -> Result<()> {
  let mut h = sumhash512::new(None)?;
  let bytes_written = h.write("hello world".as_bytes())?;
  println!("Bytes written: {}", bytes_written);
  let output = h.sum(vec![])?;
  println!("Result: {}", hex::encode(&output));

  Ok(())
}
```

Note that the API still follows a similar style to the reference implementation. However, it can probably be changed to have the same trait definitions as usual hash function implementations in the Rust ecosystem. This can also avoid some existing buffered (block size) logic.

## Cargo

### Build

Run `cargo build`.

### Tests

All the existing tests from `go-sumhash` have been ported and are green. The tests rely on generating random matrixes using `Shake256` where this library also honors the input and expected exact output match, giving confidence for correctness.

Run `cargo test`:

```bash
running 10 tests
test sumhash512::test::sumhash512_salt ... ok
test sumhash512::test::sumhash512_sizes ... ok
test sumhash512::test::sumhash512 ... ok
test sumhash512::test::sumhash512_creset ... ok
test sumhash512::test::sumhash512_checksum_with_value ... ok
test sumhash::test::hash_custom ... ok
test sumhash::test::hash_result ... ok
test sumhash512::test::test_vector ... ok
test sumhash::test::test_hash ... ok
test compress::test::compression ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.96s

   Doc-tests sumhash

running 1 test
test src/lib.rs - (line 13) ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
```

### Benchs

Adding benchmarks is planned.

## License

Licensed under either of [MIT license](LICENSE-MIT).

## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md).
