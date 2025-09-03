use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use rand_core::OsRng;

use mithril_circuits::{
    JubjubBase,
    unique_signature::{Signature, SigningKey, VerificationKey},
};

/// Benchmarks the signing operation
fn benchmark_sign(c: &mut Criterion) {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let msg = JubjubBase::random(&mut rng);

    c.bench_function("Signing a message", |b| {
        b.iter(|| {
            let _ = sk.sign(msg, &mut rng);
        })
    });
}

/// Benchmarks the signature verification operation
fn benchmark_verify(c: &mut Criterion) {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let msg = JubjubBase::random(&mut rng);
    let signature = sk.sign(msg, &mut rng);
    let vk = VerificationKey::from(&sk);

    c.bench_function("Verifying a signature", |b| {
        b.iter(|| {
            let _ = signature.verify(msg, &vk).unwrap();
        })
    });
}

criterion_group!(benches, benchmark_sign, benchmark_verify);
criterion_main!(benches);
