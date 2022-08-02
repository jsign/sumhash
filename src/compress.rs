use byteorder::ReadBytesExt;
use sha3::{digest::ExtendableOutput, Shake256};
use std::io::Write;

// Matrix is the n-by-m sumhash matrix A with elements in Z_q where q=2^64
#[derive(Clone)]
pub struct Matrix {
    matrix: Vec<Vec<u64>>,
}

// LookupTable is the precomputed sums from a matrix for every possible byte of input.
// Its dimensions are [n][m/8][256]uint64.
#[derive(Clone)]
pub struct LookupTable {
    lookup_table: Vec<Vec<[u64; 256]>>,
}

// RandomMatrix generates a random sumhash matrix by reading from rand.
// n is the number of rows in the matrix and m is the number of bits in the input message.
// must be a multiple of 8.
pub fn random_matrix<T: ReadBytesExt>(rand: &mut T, n: usize, m: usize) -> Matrix {
    if m % 8 != 0 {
        panic!("m={:?} is not a multiple of 8", m);
    }

    let mut matrix: Vec<Vec<u64>> = Vec::with_capacity(n);
    (0..n).for_each(|i| {
        matrix.push(Vec::with_capacity(m));
        (0..m).for_each(|_| {
            let e = rand.read_u64::<byteorder::LittleEndian>().unwrap();
            matrix[i].push(e);
        });
    });

    Matrix { matrix }
}

// RandomMatrixFromSeed creates a random-looking matrix to be used for the sumhash function using the seed bytes.
// n and m are the rows  and columns of the matrix respectively
#[cfg(test)]
pub fn random_matrix_from_seed(seed: &[u8], n: usize, m: usize) -> Matrix {
    let mut xof = Shake256::default();
    xof.write_all(&64u16.to_le_bytes()).unwrap();
    xof.write_all(&(n as u16).to_le_bytes()).unwrap();
    xof.write_all(&(m as u16).to_le_bytes()).unwrap();
    xof.write_all(seed).unwrap();

    random_matrix(&mut xof.finalize_xof(), n, m)
}

impl Matrix {
    // LookupTable generates a lookuptable used to increase hash calculation performance
    pub fn lookup_table(&self) -> LookupTable {
        let n = self.matrix.len();
        let m = self.matrix[0].len();

        let mut at: Vec<Vec<[u64; 256]>> = vec![vec![[0u64; 256]; m / 8]; n];
        (0..n).for_each(|i| {
            (0..m).step_by(8).for_each(|j| {
                for b in 0..256 {
                    let zz = sum_bits(&self.matrix[i][j..j + 8], b as u8);
                    at[i][j / 8][b] = zz;
                }
            });
        });

        LookupTable { lookup_table: at }
    }
}

fn sum_bits(a: &[u64], b: u8) -> u64 {
    // the following code is an optimization for this loop
    // for i := 0; i < 8; i++ {
    //   if b>>i&1 == 1 {
    //     x += as[i]
    //   }
    // }

    let a0 = a[0] & -i64::from(b & 1) as u64;
    let a1 = a[1] & -i64::from((b >> 1) & 1) as u64;
    let a2 = a[2] & -i64::from((b >> 2) & 1) as u64;
    let a3 = a[3] & -i64::from((b >> 3) & 1) as u64;
    let a4 = a[4] & -i64::from((b >> 4) & 1) as u64;
    let a5 = a[5] & -i64::from((b >> 5) & 1) as u64;
    let a6 = a[6] & -i64::from((b >> 6) & 1) as u64;
    let a7 = a[7] & -i64::from((b >> 7) & 1) as u64;

    a0.wrapping_add(a1)
        .wrapping_add(a2)
        .wrapping_add(a3)
        .wrapping_add(a4)
        .wrapping_add(a5)
        .wrapping_add(a6)
        .wrapping_add(a7)
}

// Compressor represents the compression function which is performed on a message
pub trait Compressor: Clone {
    fn compress(&self, dst: &mut [u8], src: &[u8]);
    fn input_len(&self) -> usize; // len(input)
    fn output_len(&self) -> usize; // len(dst)
}

impl Compressor for Matrix {
    // input_len returns the valid length of a message in bytes
    fn input_len(&self) -> usize {
        self.matrix[0].len() / 8
    }

    // output_len returns the output len in bytes of the compression function
    fn output_len(&self) -> usize {
        self.matrix.len() * 8
    }

    // Compress performs the compression algorithm on a message and output into dst
    fn compress(&self, dst: &mut [u8], msg: &[u8]) {
        if msg.len() != self.input_len() {
            panic!(
                "could not compress message. input size is wrong. size is {:?}, expected {:?}",
                msg.len(),
                self.input_len()
            );
        }
        if dst.len() != self.output_len() {
            panic!(
                "could not compress message. output size is wrong size is {:?}, expected {:?}",
                dst.len(),
                self.output_len()
            )
        }

        // this allows go to eliminate the bound check when accessing the slice
        // _ = msg[A.input_len()-1]
        // _ = dst[A.output_len()-1]

        (0..self.matrix.len()).for_each(|i| {
            let mut x = 0u64;

            (0..msg.len()).for_each(|j| {
                // the following code is an optimization for this loop
                // for b := 0; b < 8; b++ {
                //   if (msg[j]>>b)&1 == 1 {
                //     x += A[i][8*j+b]
                //   }
                // }
                let a0 = self.matrix[i][8 * j] & -i64::from(msg[j] & 1) as u64;
                let a1 = self.matrix[i][8 * j + 1] & -i64::from((msg[j] >> 1) & 1) as u64;
                let a2 = self.matrix[i][8 * j + 2] & -i64::from((msg[j] >> 2) & 1) as u64;
                let a3 = self.matrix[i][8 * j + 3] & -i64::from((msg[j] >> 3) & 1) as u64;
                let a4 = self.matrix[i][8 * j + 4] & -i64::from((msg[j] >> 4) & 1) as u64;
                let a5 = self.matrix[i][8 * j + 5] & -i64::from((msg[j] >> 5) & 1) as u64;
                let a6 = self.matrix[i][8 * j + 6] & -i64::from((msg[j] >> 6) & 1) as u64;
                let a7 = self.matrix[i][8 * j + 7] & -i64::from((msg[j] >> 7) & 1) as u64;
                x = x
                    .wrapping_add(a0)
                    .wrapping_add(a1)
                    .wrapping_add(a2)
                    .wrapping_add(a3)
                    .wrapping_add(a4)
                    .wrapping_add(a5)
                    .wrapping_add(a6)
                    .wrapping_add(a7);
            });

            dst[8 * i..8 * i + 8].clone_from_slice(&x.to_le_bytes());
        })
    }
}

impl Compressor for LookupTable {
    // input_len returns the valid length of a message in bytes
    fn input_len(&self) -> usize {
        self.lookup_table[0].len()
    }

    // output_len returns the output len in bytes of the compression function
    fn output_len(&self) -> usize {
        self.lookup_table.len() * 8
    }

    // Compress performs the compression algorithm on a message and output into dst
    fn compress(&self, dst: &mut [u8], msg: &[u8]) {
        if msg.len() != self.input_len() {
            panic!(
                "could not compress message. input size is wrong. size is {:?}, expected {:?}",
                msg.len(),
                self.input_len()
            )
        }
        if dst.len() != self.output_len() {
            panic!(
                "could not compress message. output size is wrong size is {:?}, expected {:?}",
                dst.len(),
                self.output_len()
            )
        }

        // this allows go to eliminate the bound check when accessing the slice
        //_ = msg[A.input_len()-1]
        //_ = dst[A.output_len()-1]

        (0..self.lookup_table.len()).for_each(|i| {
            let mut x = 0u64;

            (0..self.lookup_table[i].len()).for_each(|j| {
                x = x.wrapping_add(self.lookup_table[i][j][msg[j] as usize]);
            });

            dst[8 * i..8 * i + 8].clone_from_slice(&x.to_le_bytes());
        });
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    #[test]
    fn compression() {
        let n = 14;
        let m = n * 64 * 2;

        let mut rand = Shake256::default().finalize_xof();
        let a = random_matrix(&mut rand, n, m);
        let at = a.lookup_table();

        assert_eq!(a.input_len(), m / 8, "unexpected input len (A)");
        assert_eq!(at.input_len(), m / 8, "unexpected input len (At)");
        assert_eq!(a.output_len(), n * 8, "unexpected output len (A)");
        assert_eq!(at.output_len(), n * 8, "unexpected output len (At)");

        let mut dst1 = vec![0u8; a.output_len()];
        let mut dst2 = vec![0u8; a.output_len()];

        (0..1000).for_each(|_| {
            let msg: Vec<u8> = vec![1u8; a.input_len()]; // (0..a.input_len()).map(|_| rand::random::<u8>()).collect();
            a.compress(&mut dst1, &msg);
            at.compress(&mut dst2, &msg);

            assert_eq!(dst1, dst2, "matrix and lookup table outputs are different");
        });
    }
}
