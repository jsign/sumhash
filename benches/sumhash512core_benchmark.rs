use criterion::{criterion_group, criterion_main, Criterion};
use digest::Update;
use digest::{core_api::CoreWrapper, FixedOutput};
use rand::Rng;
use sumhash::sumhash512core::AlgorandSumhash512Core;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rnd = rand::thread_rng();
    let mut buf = [0; 600];
    for i in buf.iter_mut() {
        *i = rnd.gen();
    }

    c.bench_function("hash 600 bytes", |b| {
        b.iter(|| {
            let mut cw = CoreWrapper::<AlgorandSumhash512Core>::default();
            cw.update(&buf);
            cw.finalize_fixed();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
