use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tequel_rs::encrypt::TequelEncrypt; 
use rayon::prelude::*;

fn bench_encrypt_1kb(c: &mut Criterion) {
    let mut teq = TequelEncrypt::new();
    let data = vec![0u8; 1024];
    let key = "secure_password";

    c.bench_function("tequel_encrypt_1kb", |b| {
        b.iter(|| {
            teq.encrypt(black_box(&data), black_box(key)).unwrap()
        })
    });
}


fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("tequel_throughput");
    group.measurement_time(std::time::Duration::from_secs(20));
    
    let mut teq = TequelEncrypt::new();

    let key = "master_key_v0.4.1";

    for size in [1024, 1024 * 1024, 5 * 1024 * 1024].iter() {
        let data = vec![0u8; *size];
        group.throughput(criterion::Throughput::Bytes(*size as u64));

        group.bench_with_input(criterion::BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| teq.encrypt(black_box(&data), black_box(key)).unwrap())
        });
    }

    group.finish();
}



fn bench_parallel_stress(c: &mut Criterion) {
    let key = "parallel_key";
    let data_chunks: Vec<Vec<u8>> = (0..100).map(|_| vec![0u8; 10240]).collect();
    
    c.bench_function("tequel_parallel_100_chunks", |b| {
        b.iter(|| {
            data_chunks.par_iter().for_each(|chunk| {
                let mut teq = TequelEncrypt::new();
                let _ = teq.encrypt(black_box(chunk), black_box(key)).unwrap();
            });
        })
    });

}




criterion_group!(benches, bench_encrypt_1kb, bench_throughput, bench_parallel_stress);
criterion_main!(benches);