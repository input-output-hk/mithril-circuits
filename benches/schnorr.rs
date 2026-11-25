//! Native compact Schnorr signing and verification benchmarks.
//!
//! Run `cargo bench --bench schnorr`. Key generation and message selection
//! happen outside the timed loops. Signing includes OS-backed nonce generation;
//! verification checks a compact `(sigma, s, c)` signature prepared before
//! timing starts, including hash-to-curve and both commitment reconstructions.

use criterion::{Criterion, criterion_group, criterion_main};
use ff::Field;
use rand_core::OsRng;

use snark_stms::{
    JubjubBase,
    schnorr_signature::{SigningKey, VerificationKey},
};

/// Benchmarks the signing operation.
fn benchmark_sign(c: &mut Criterion) {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let msg = JubjubBase::random(&mut rng);

    c.bench_function("Signing a message", |b| {
        b.iter(|| {
            let _ = sk.sign(&[msg], &mut rng);
        })
    });
}

/// Benchmarks the signature verification operation.
fn benchmark_verify(c: &mut Criterion) {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let msg = JubjubBase::random(&mut rng);
    let signature = sk.sign(&[msg], &mut rng);
    let vk = VerificationKey::from(&sk);

    c.bench_function("Verifying a signature", |b| {
        b.iter(|| {
            signature.verify(&[msg], &vk).unwrap();
        })
    });
}

criterion_group!(benches, benchmark_sign, benchmark_verify);
criterion_main!(benches);
