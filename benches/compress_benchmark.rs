use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha3::{digest::ExtendableOutput, Shake256};
use sumhash::compress;

pub fn criterion_benchmark(c: &mut Criterion) {
    let a = compress::random_matrix(&mut Shake256::default().finalize_xof(), 8, 1024);
    c.bench_function("create matrix", |b| {
        b.iter(|| {
            a.lookup_table();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
