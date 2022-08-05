use std::io::Write;

use anyhow::Result;
use digest::{
    block_buffer::Eager,
    core_api::{Buffer, BufferKindUser, FixedOutputCore, UpdateCore},
    crypto_common::{Block, BlockSizeUser},
    typenum::U64,
    HashMarker, Output, OutputSizeUser, Update,
};

use byteorder::{ByteOrder, LittleEndian};

use crate::compress::{self, Compressor, LookupTable};

/// The size in bytes of the sumhash checksum.
pub const DIGEST_SIZE: usize = 64;

/// Block size, in bytes, of the sumhash hash function.
pub const DIGEST_BLOCK_SIZE: usize = 64;

struct SumhashCore {
    c: LookupTable,
    h: Vec<u8>, // hash chain (from last compression, or IV)
    len: u64,
    salt: Option<Vec<u8>>,
}

impl SumhashCore {
    fn new(salt: Option<Vec<u8>>) -> Result<Self> {
        let matrix = compress::random_matrix_from_seed("Algorand".as_bytes(), 8, 1024);
        let c = matrix.lookup_table();
        Ok(Self {
            c,
            salt,
            h: vec![0; DIGEST_SIZE],
            len: 0,
        })
    }

    fn update(&mut self, data: &[u8]) {
        let mut cin = [0u8; 128];
        self.len += data.len() as u64;
        cin[0..DIGEST_BLOCK_SIZE]
            .as_mut()
            .write_all(&self.h)
            .unwrap();

        match self.salt {
            Some(ref salt) => {
                SumhashCore::xor_bytes(&mut cin[DIGEST_BLOCK_SIZE..], data, salt);
            }
            None => {
                cin[DIGEST_BLOCK_SIZE..].as_mut().write_all(data).unwrap();
            }
        }

        self.c.compress(&mut self.h, &cin);
    }

    fn xor_bytes(dst: &mut [u8], a: &[u8], b: &[u8]) {
        dst.iter_mut()
            .enumerate()
            .for_each(|(i, val)| *val = a[i] ^ b[i]);
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

impl FixedOutputCore for SumhashCore {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bitlen = (self.len + buffer.get_pos() as u64) << 3; // number of input bits written

        let mut tmp = [0; 16];
        LittleEndian::write_u64(&mut tmp[0..], bitlen);
        LittleEndian::write_u64(&mut tmp[8..], 0);
        buffer.digest_pad(0x01, &tmp, |a| self.update(a));

        out.copy_from_slice(&self.h);
    }
}

impl UpdateCore for SumhashCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        /*
               println!("called update_blocks()");
               for i in blocks.iter().enumerate() {
                   println!("Post {} = {:?}", i.0, i.1);
               }
        */
        // TODO(jsign): avoid alloc.

        for b in blocks {
            self.update(b)
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use digest::core_api::CoreWrapper;
    use digest::{
        block_buffer::Eager,
        core_api::{BufferKindUser, UpdateCore},
        crypto_common::{Block, BlockSizeUser},
        typenum::U64,
        FixedOutput, HashMarker, Output, OutputSizeUser, Update,
    };
    use sha3::{
        digest::{ExtendableOutput, XofReader},
        Shake256,
    };
    use std::io::Write;

    #[test]
    fn jjjsumhash512() {
        let mut input = vec![0; 6000];
        let mut v = Shake256::default();
        v.write_all("sumhash input".as_bytes()).unwrap();
        v.finalize_xof().read(&mut input);

        let mut h = CoreWrapper::<SumhashCore>::default();
        h.update(&input);

        let sum = h.finalize_fixed();
        let expected_sum = "43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6";
        assert_eq!(
            hex::encode(&sum),
            expected_sum,
            "got {}, want {}",
            hex::encode(&sum),
            expected_sum,
        )
    }
}
