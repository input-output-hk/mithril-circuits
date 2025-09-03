use blst::BLST_ERROR::BLST_SUCCESS;
use blst::min_sig::SecretKey;
use criterion::{Criterion, criterion_group, criterion_main};
use rand_core::{OsRng, RngCore};

fn benchmark_sign(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    c.bench_function("Create a BLS signature", |b| {
        b.iter(|| {
            let _ = sk.sign(&msg, &[], &[]);
        })
    });
}

fn benchmark_verify(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let vk = sk.sk_to_pk();
    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let sig = sk.sign(&msg, &[], &[]);

    c.bench_function("Verifying a single BLS signature", |b| {
        b.iter(|| {
            let res = sig.verify(false, &msg, &[], &[], &vk, false);
            assert_eq!(res, BLST_SUCCESS);
        })
    });
}

criterion_group!(benches, benchmark_sign, benchmark_verify);
criterion_main!(benches);
