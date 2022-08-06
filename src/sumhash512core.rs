use digest::{
    block_buffer::Eager,
    core_api::{Buffer, BufferKindUser, FixedOutputCore, UpdateCore},
    crypto_common::{Block, BlockSizeUser},
    typenum::U64,
    HashMarker, Output, OutputSizeUser, Reset,
};

use byteorder::{ByteOrder, LittleEndian};

use crate::compress::{Compressor, LookupTable, Matrix};

/// The size in bytes of the sumhash checksum.
pub const DIGEST_SIZE: usize = 64;

/// Block size, in bytes, of the sumhash hash function.
pub const DIGEST_BLOCK_SIZE: usize = 64;

/// AlgorandSumhash512 is an Algorand instance of Sumhash512Core with a lookup table as compressor.
pub type AlgorandSumhash512Core = Sumhash512Core<LookupTable>;

impl AlgorandSumhash512Core {
    /// new_with_salt returns a Sumhash512 with salt.
    pub fn new_with_salt(salt: [u8; DIGEST_BLOCK_SIZE]) -> Self {
        let mut s = Self {
            salt: Some(salt),
            ..Default::default()
        };
        s.compress_block(&[0; DIGEST_SIZE]);
        s
    }
}

impl Default for AlgorandSumhash512Core {
    fn default() -> Self {
        let c = Matrix::random_from_seed("Algorand".as_bytes(), 8, 1024);
        Sumhash512Core::new(c.lookup_table(), None)
    }
}

/// Sumhash512Core returns a core implementation for sumhash cryptographic hash function.
pub struct Sumhash512Core<C: Compressor> {
    c: C,
    h: [u8; DIGEST_SIZE], // hash chain (from last compression, or IV)
    len: u64,
    salt: Option<[u8; DIGEST_BLOCK_SIZE]>,
}

impl<C: Compressor> Sumhash512Core<C> {
    fn new(c: C, salt: Option<[u8; DIGEST_BLOCK_SIZE]>) -> Self {
        Self {
            c,
            h: [0; DIGEST_SIZE],
            salt,
            len: 0,
        }
    }

    fn compress_block(&mut self, data: &[u8]) {
        let mut cin = [0; DIGEST_BLOCK_SIZE * 2];
        self.len += data.len() as u64;

        cin[0..DIGEST_BLOCK_SIZE].clone_from_slice(&self.h);
        match self.salt {
            Some(ref salt) => cin[DIGEST_BLOCK_SIZE..]
                .iter_mut()
                .enumerate()
                .for_each(|(i, val)| *val = data[i] ^ salt[i]),
            None => cin[DIGEST_BLOCK_SIZE..].clone_from_slice(data),
        }

        self.c.compress(&mut self.h, &cin);
    }
}

impl<C: Compressor> Reset for Sumhash512Core<C> {
    fn reset(&mut self) {
        self.h = [0; DIGEST_SIZE];
        self.len = 0;
        if self.salt.is_some() {
            // Write an initial block of zeros, effectively
            // prepending the salt to the input.
            self.compress_block(&[0; DIGEST_SIZE]);
        }
    }
}

impl<C: Compressor> HashMarker for Sumhash512Core<C> {}

impl<C: Compressor> BlockSizeUser for Sumhash512Core<C> {
    type BlockSize = U64;
}

impl<C: Compressor> BufferKindUser for Sumhash512Core<C> {
    type BufferKind = Eager;
}

impl<C: Compressor> OutputSizeUser for Sumhash512Core<C> {
    type OutputSize = U64;
}

impl<C: Compressor> FixedOutputCore for Sumhash512Core<C> {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bitlen = (self.len + buffer.get_pos() as u64) << 3; // number of input bits written
        let mut tmp = [0; 16];
        LittleEndian::write_u64(&mut tmp, bitlen);
        buffer.digest_pad(0x01, &tmp, |a| self.compress_block(a));

        out.copy_from_slice(&self.h);
    }
}

impl<C: Compressor> UpdateCore for Sumhash512Core<C> {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for b in blocks {
            self.compress_block(b)
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::io::Write;

    use super::*;
    use digest::{core_api::CoreWrapper, FixedOutput, Update};
    use sha3::{
        digest::{ExtendableOutput, XofReader},
        Shake256,
    };

    struct TestElement {
        input: &'static str,
        output: &'static str,
    }

    static TEST_VECTOR: &[TestElement] = &[
        TestElement{
            input:"",
            output:"591591c93181f8f90054d138d6fa85b63eeeb416e6fd201e8375ba05d3cb55391047b9b64e534042562cc61944930c0075f906f16710cdade381ee9dd47d10a0",
        },
        TestElement{
            input:"a",
            output:"ea067eb25622c633f5ead70ab83f1d1d76a7def8d140a587cb29068b63cb6407107aceecfdffa92579ed43db1eaa5bbeb4781223a6e07dd5b5a12d5e8bde82c6",
        },
        TestElement{
            input: "ab",
            output:"ef09d55b6add510f1706a52c4b45420a6945d0751d73b801cbc195a54bc0ade0c9ebe30e09c2c00864f2bd1692eba79500965925e2be2d1ac334425d8d343694",
        },
        TestElement{
            input:"abc",
            output: "a8e9b8259a93b8d2557434905790114a2a2e979fbdc8aa6fd373315a322bf0920a9b49f3dc3a744d8c255c46cd50ff196415c8245cdbb2899dec453fca2ba0f4",
        },
        TestElement{
            input:"abcd",
            output:"1d4277f17e522c4607bc2912bb0d0ac407e60e3c86e2b6c7daa99e1f740fe2b4fc928defad8e1ccc4e7d96b79896ffe086836c172a3db40a154d2229484f359b",
        },
        TestElement{
            input:"You must be the change you wish to see in the world. -Mahatma Gandhi",
            output:"5c5f63ac24392d640e5799c4164b7cc03593feeec85844cc9691ea0612a97caabc8775482624e1cd01fb8ce1eca82a17dd9d4b73e00af4c0468fd7d8e6c2e4b5",
        },
        TestElement{
            input:"I think, therefore I am. – Rene Descartes.",
            output:"2d4583cdb18710898c78ec6d696a86cc2a8b941bb4d512f9d46d96816d95cbe3f867c9b8bd31964406c847791f5669d60b603c9c4d69dadcb87578e613b60b7a",
        },
    ];

    #[test]
    fn test_vector() {
        TEST_VECTOR.iter().enumerate().for_each(|(i, element)| {
            let mut h = CoreWrapper::<AlgorandSumhash512Core>::default();

            h.update(element.input.as_bytes());

            let sum = hex::encode(h.finalize_fixed());
            assert_eq!(
                element.output, sum,
                "test vector element mismatched on index {} failed! got {}, want {}",
                i, sum, element.output
            );
        })
    }

    #[test]
    fn sumhash512() {
        let mut input = [0; 6000];
        let mut v = Shake256::default();
        v.write_all("sumhash input".as_bytes()).unwrap();
        v.finalize_xof().read(&mut input);

        let mut h = CoreWrapper::<AlgorandSumhash512Core>::default();
        h.update(&input);
        let sum = hex::encode(h.finalize_fixed());

        let expected_sum = "43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6";
        assert_eq!(sum, expected_sum, "got {}, want {}", sum, expected_sum,)
    }

    #[test]
    fn sumhash512_salt() {
        let mut input = [0; 6000];
        let mut v = Shake256::default();
        v.write_all("sumhash input".as_bytes()).unwrap();
        v.finalize_xof().read(&mut input);

        let mut salt = [0; 64];
        v = Shake256::default();
        v.write_all("sumhash salt".as_bytes()).unwrap();
        v.finalize_xof().read(&mut salt);

        let mut h = CoreWrapper::from_core(Sumhash512Core::new_with_salt(salt));
        h.update(&input);

        let sum = hex::encode(&h.finalize_fixed());
        let expected_sum = "c9be08eed13218c30f8a673f7694711d87dfec9c7b0cb1c8e18bf68420d4682530e45c1cd5d886b1c6ab44214161f06e091b0150f28374d6b5ca0c37efc2bca7";
        assert_eq!(sum, expected_sum, "got {}, want {}", sum, expected_sum);
    }

    #[test]
    fn sumhash512_reset() {
        let mut input = [0; 6000];
        let mut v = Shake256::default();
        v.write_all("sumhash".as_bytes()).unwrap();
        v.finalize_xof().read(&mut input);

        let mut h = CoreWrapper::<AlgorandSumhash512Core>::default();
        h.write_all(&input).unwrap();
        h.update(&input);

        let mut input = [0; 6000];
        v = Shake256::default();
        v.write_all("sumhash input".as_bytes()).unwrap();
        v.finalize_xof().read(&mut input);

        h.reset();
        h.update(&input);

        let sum = hex::encode(h.finalize_fixed());
        let expected_sum = "43dc59ca43da473a3976a952f1c33a2b284bf858894ef7354b8fc0bae02b966391070230dd23e0713eaf012f7ad525f198341000733aa87a904f7053ce1a43c6";
        assert_eq!(sum, expected_sum, "got {}, want {}", sum, expected_sum);
    }
}
