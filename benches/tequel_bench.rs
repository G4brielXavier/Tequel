use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput, BenchmarkId};
use tequel::encrypt::TequelEncrypt; 
use rayon::prelude::*;
use std::time::Duration;
use sha2::{Sha384, Digest};

fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("tequel_core_performance");
    group.measurement_time(Duration::from_secs(10));
    

    let mut teq = TequelEncrypt::new();
    let key = "master_key_v1.2.0";

    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let _ = black_box(teq.encrypt(black_box(&data), black_box(key)));
            })
        });
    }

    group.finish();
}

fn bench_parallel_stress(c: &mut Criterion) {
    let data_chunks: Vec<Vec<u8>> = (0..64).map(|_| vec![0u8; 1024 * 1024]).collect();
    
    c.bench_function("tequel_parallel_raw_speed", |b| {
        b.iter(|| {
            data_chunks.par_iter().for_each(|chunk| {
                let mut teq = tequel::hash::TequelHash::new(); 
                black_box(teq.tqlhash(black_box(chunk)));
            });
        })
    });
}

fn bench_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Security_Performance_Battle");
    let size = 1024 * 1024;
    let data = vec![0u8; size];
    
    group.throughput(Throughput::Bytes(size as u64));

    group.bench_function("Standard_SHA384", |b| {
        b.iter(|| {
            let mut hasher = Sha384::new();
            hasher.update(black_box(&data));
            black_box(hasher.finalize());
        })
    });

    let mut teq = tequel::hash::TequelHash::new();
    group.bench_function("Tequel_TQL11_384", |b| {
        b.iter(|| {
            black_box(teq.tqlhash(black_box(&data)));
        })
    });

    group.finish();
}

fn bench_multi_core_battle(c: &mut Criterion) {
    let mut group = c.benchmark_group("MultiCore_Performance_100MB");
    

    let total_size = 100 * 1024 * 1024;
    let chunk_size = 1024 * 1024;
    let data_chunks: Vec<Vec<u8>> = (0..100).map(|_| vec![0u8; chunk_size]).collect();

    group.throughput(Throughput::Bytes(total_size as u64));


    group.bench_function("Parallel_SHA384", |b| {
        b.iter(|| {
            data_chunks.par_iter().for_each(|chunk| {
                let mut hasher = Sha384::new();
                hasher.update(black_box(chunk));
                let _ = black_box(hasher.finalize());
            });
        })
    });

    group.bench_function("Parallel_Tequel_TQL11", |b| {
        b.iter(|| {
            data_chunks.par_iter().for_each(|chunk| {
                let mut teq = tequel::hash::TequelHash::new();
                let _ = black_box(teq.tqlhash(black_box(chunk)));
            });
        })
    });

    group.finish();
}

criterion_group!(benches, bench_multi_core_battle, bench_comparison, bench_throughput, bench_parallel_stress);
criterion_main!(benches);
