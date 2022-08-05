use crate::compress;
use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use std::io::Write;

/// `Digest` provides the hash state for calculating a subset-sum hash function.
pub struct Digest<T: compress::Compressor> {
    c: T,
    size: usize,       // number of bytes in a hash output
    block_size: usize, // number of bytes in an input block, per compression

    h: Vec<u8>, // hash chain (from last compression, or IV)
    x: Vec<u8>, // data written since last compression
    nx: usize,  // number of input bytes written since last compression
    len: u64,   // total number of input bytes written overall

    salt: Option<Vec<u8>>, // salt block
}

// `Digest<C>` implementation is based on: https://github.com/algorand/go-sumhash/blob/master/sumhash.go
impl<C: compress::Compressor> Digest<C> {
    /// Returns a `Digest` with the specified `Compressor`.
    /// If salt is `None`, the hash is calculated in unsalted mode.
    /// Otherwise, salt should be `BlockSize(c)` bytes, and the hash is computed in salted mode.
    pub fn new(c: C, salt: Option<Vec<u8>>) -> Result<Digest<C>> {
        let output_len = c.output_len();
        let input_len = c.input_len();

        let mut d = Digest {
            c,
            size: output_len,
            block_size: input_len - output_len,

            h: vec![0; output_len],
            x: vec![0; input_len - output_len],
            nx: 0,
            len: 0,

            salt,
        };

        if let Some(ref salt) = d.salt {
            if salt.len() != d.block_size {
                panic!("bad salt size: want {}, got {}", d.block_size, salt.len())
            }
        }

        d.reset();

        Ok(d)
    }

    /// `reset` resets the state of the hash so it can be reused.
    pub fn reset(&mut self) {
        self.h.iter_mut().for_each(|a| *a = 0);
        self.nx = 0;
        self.len = 0;
        if self.salt.is_some() {
            // Write an initial block of zeros, effectively
            // prepending the salt to the input.
            let zeros = vec![0u8; self.block_size];
            self.write(&zeros).unwrap();
        }
    }

    /// `size` returns the size of the hash output.
    pub fn size(&self) -> usize {
        self.size
    }

    /// `block_size` returns the block size for the hash function.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// `write` adds more data to the running hash.
    pub fn write(&mut self, mut p: &[u8]) -> Result<usize> {
        let nn = p.len();

        // Check if the new length (in bits) overflows our counter capacity.
        if nn as u64 >= (1 << 61) - self.len {
            panic!(
                "length overflow: already wrote {} bytes, trying to write {} bytes",
                self.len, nn
            );
        }

        self.len += nn as u64;
        if self.nx > 0 {
            // continue with existing buffer, if nonempty
            let n = self.x[self.nx..].as_mut().write(p)?;

            self.nx += n;
            if self.nx == self.block_size {
                blocks(self, &self.x.clone());
                self.nx = 0
            }
            p = &p[n..];
        }

        if p.len() >= self.block_size {
            // handle any remaining full input blocks
            let n = p.len() / self.block_size * self.block_size;
            blocks(self, &p[..n]);
            p = &p[n..];
        }
        if !p.is_empty() {
            // handle any remaining input
            match self.x.as_mut_slice().write(p) {
                Ok(s) => self.nx = s,
                Err(_) => panic!("copying data"),
            }
        }

        Ok(nn)
    }

    // TODO(jsign): impl copy.
    fn copy(&self) -> Self {
        Digest {
            c: self.c.clone(),
            size: self.size,
            block_size: self.block_size,
            h: self.h.clone(),
            x: self.x.clone(),
            nx: self.nx,
            len: self.len,
            salt: self.salt.clone(),
        }
    }

    /// `sum` appends the current hash to b and returns the resulting slice.
    /// It does not change the underlying hash state.
    pub fn sum(&self, mut iin: Vec<u8>) -> Result<Vec<u8>> {
        // TODO(jsign): receiving Vec<u8> might not be ideal.
        // Make a copy of d so that caller can keep writing and summing.
        let mut d0 = self.copy();
        let hash = d0.check_sum()?;
        iin.extend(&hash);
        Ok(iin)
    }

    fn check_sum(&mut self) -> Result<Vec<u8>> {
        let b = self.block_size;
        let p = b - 16;

        let bitlen = self.len << 3; // number of input bits written

        // Padding. Add a 1 bit and 0 bits until P bytes mod B.
        // The padding byte is 0x01 since sumhash reads bits in little-endian order.
        let mut tmp = vec![0; b];
        tmp[0] = 0x01;
        if self.len % (b as u64) < p as u64 {
            self.write(&tmp[0..p - (self.len as u64 % b as u64) as usize])?;
        } else {
            self.write(&tmp[0..b + p - (self.len as u64 % b as u64) as usize])?;
        }

        // Write length in bits, using 128 bits (16 bytes) to represent it.
        // The upper 64 bits are always zero, because bitlen has type uint64.
        LittleEndian::write_u64(&mut tmp[0..], bitlen);
        LittleEndian::write_u64(&mut tmp[8..], 0);
        self.write(&tmp[0..16])?;

        if self.nx != 0 {
            // buffer must be empty now
            panic!("d.nx != 0")
        }

        Ok(self.h.clone())
    }
}
// `blocks` hashes full blocks of data. len(data) must be a multiple of d.blockSize.
fn blocks<C: compress::Compressor>(d: &mut Digest<C>, data: &[u8]) {
    let mut cin = vec![0u8; d.c.input_len()];

    (0..data.len() - d.block_size + 1)
        .step_by(d.block_size)
        .for_each(|i| {
            cin[0..d.size].as_mut().write_all(&d.h).unwrap();

            let input = &data[i..i + d.block_size];
            if let Some(ref salt) = d.salt {
                xor_bytes(cin[d.size..d.size + d.block_size].as_mut(), input, salt);
            } else {
                cin[d.size..d.size + d.block_size]
                    .as_mut()
                    .write_all(input)
                    .unwrap();
            }

            d.c.compress(&mut d.h, &cin);
        })
}

fn xor_bytes(dst: &mut [u8], a: &[u8], b: &[u8]) {
    dst.iter_mut()
        .enumerate()
        .for_each(|(i, val)| *val = a[i] ^ b[i]);
}

#[cfg(test)]
pub mod test {
    use std::io::Read;

    use super::*;
    use crate::compress::*;
    use anyhow::Result;
    use hex;
    use sha3::{digest::ExtendableOutput, Shake256};

    #[test]
    fn test_hash() {
        test_hash_params(14, 14 * 64 * 4).unwrap();
        test_hash_params(10, 10 * 64 * 2).unwrap();
    }

    #[test]
    fn hash_result() -> Result<()> {
        let test_element = [
            "1234567890",
            "fc91828801365750f0267edd5530a301d1471736c485472bbadf22507731a81fd67e0d80cce722a81c6dc690b698f5771713855c5d1927488d79713e3abd81053de2c7db1430b8fb106b3f6aa6b93e54aec351e47bcc176c0df58a0336d24979a064f3acb67a693db399c6402149157b"
            ];

        let a = compress::random_matrix_from_seed(&[0x11, 0x22, 0x33, 0x44], 14, 14 * 64 * 4);
        let a_t = a.lookup_table();

        let mut h1 = Digest::new(a, None)?;
        let mut h2 = Digest::new(a_t, None)?;

        let bytes_written = h1.write(test_element[0].as_bytes())?;
        assert_eq!(bytes_written, test_element[0].len());

        let bytes_written = h2.write(test_element[0].as_bytes())?;
        assert_eq!(bytes_written, test_element[0].len());

        let digset1 = h1.sum(vec![])?;
        let digset2 = h2.sum(vec![])?;

        assert_eq!(digset1, digset2);

        let result = hex::decode(test_element[1])?;

        assert_eq!(
            digset1,
            result,
            "result is {} expected {}",
            hex::encode(&digset1),
            hex::encode(&result),
        );

        Ok(())
    }

    #[test]
    fn hash_custom() -> Result<()> {
        let a = compress::random_matrix_from_seed(&[0x11, 0x22, 0x33, 0x44], 14, 14 * 64 * 4);

        let mut h1 = Digest::new(a, None)?;

        let payload = "1";
        let bytes_written = h1.write(payload.as_bytes())?;
        assert_eq!(bytes_written, payload.len());

        let digset1 = h1.sum(vec![])?;

        println!("Result: {}", hex::encode(&digset1));

        Ok(())
    }

    fn test_hash_params(n: usize, m: usize) -> Result<()> {
        let mut rand = Shake256::default().finalize_xof();
        let a = compress::random_matrix(&mut rand, n, m);
        let a_t = a.lookup_table();

        let input_len = a.input_len();
        let mut h1 = Digest::new(a, None)?;
        assert_eq!(h1.size(), n * 8, "h1 has unexpected size");
        assert_eq!(
            h1.block_size(),
            m / 8 - n * 8,
            "h1 has unexpected block size"
        );

        let mut h2 = Digest::new(a_t, None)?;
        assert_eq!(h2.size(), n * 8, "h2 has unexpected size");
        assert_eq!(
            h2.block_size(),
            m / 8 - n * 8,
            "h2 has unexpected block size"
        );

        for l in [1, 64, 100, 128, input_len, 6000, 6007] {
            let mut msg = vec![0; l];
            rand.read_exact(&mut msg)?;

            h1.write(&msg)?;
            h2.write(&msg)?;

            let digset1 = h1.sum(vec![])?;
            let digset2 = h2.sum(vec![])?;
            assert_eq!(digset1, digset2, "matrix and lookup table hashes differ");

            h1.reset();
            h2.reset();
        }
        Ok(())
    }
}
