use anyhow::Result;
use digest::{
    block_buffer::Eager,
    core_api::{BufferKindUser, UpdateCore},
    crypto_common::{Block, BlockSizeUser},
    typenum::U64,
    FixedOutput, HashMarker, Output, OutputSizeUser, Update,
};

use crate::{
    compress::{self, LookupTable},
    sumhash::Digest,
};

struct SumhashCore {
    d: Digest<LookupTable>,
}

impl SumhashCore {
    fn new(salt: Option<Vec<u8>>) -> Result<Self> {
        let matrix = compress::random_matrix_from_seed("Algorand".as_bytes(), 8, 1024);
        let lookup_table = matrix.lookup_table();
        let digest = Digest::new(lookup_table, salt)?;
        Ok(Self { d: digest })
    }
}

impl Default for SumhashCore {
    fn default() -> Self {
        Self::new(None).unwrap()
    }
}

impl HashMarker for SumhashCore {}

impl BlockSizeUser for SumhashCore {
    type BlockSize = U64;
}

impl BufferKindUser for SumhashCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for SumhashCore {
    type OutputSize = U64;
}

impl Update for SumhashCore {
    fn update(&mut self, data: &[u8]) {
        println!("update() called");
        todo!()
    }
}

impl FixedOutput for SumhashCore {
    fn finalize_into(self, out: &mut Output<Self>) {}
}

impl UpdateCore for SumhashCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        println!("called update_blocks()");
        for i in blocks.iter().enumerate() {
            println!("Post {} = {:?}", i.0, i.1);
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use digest::core_api::CoreWrapper;

    #[test]
    fn jjj() {
        let mut a = CoreWrapper::<SumhashCore>::default();
        println!("Block size is {}", CoreWrapper::<SumhashCore>::block_size());

        a.update(&[0x41; (63 + 2 * 64)]);
        println!("wrote two 0x41");
        a.update(&[0x41; 61]);
    }
}
