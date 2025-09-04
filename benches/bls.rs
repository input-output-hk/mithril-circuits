use blake2::{Blake2b, Digest};
use blst::min_sig::{PublicKey, Signature};
use blst::{
    BLST_ERROR::BLST_SUCCESS, blst_p1, blst_p1_affine, blst_p1_from_affine, blst_p1_to_affine,
    blst_p2, blst_p2_affine, blst_p2_from_affine, blst_p2_to_affine, min_sig::SecretKey,
    p1_affines, p2_affines,
};
use criterion::{Criterion, criterion_group, criterion_main};
use digest::consts::U16;
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

fn aggregate_and_verify(c: &mut Criterion, num_signatures: usize) {
    let mut rng = OsRng;
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sks = (0..num_signatures)
        .map(|_| SecretKey::key_gen(&ikm, &[]).unwrap())
        .collect::<Vec<_>>();
    let vks = sks.iter().map(|sk| sk.sk_to_pk()).collect::<Vec<_>>();

    let mut msg = [0u8; 32];
    rng.fill_bytes(&mut msg);

    let sigs = sks
        .iter()
        .map(|sk| sk.sign(&msg, &[], &[]))
        .collect::<Vec<_>>();

    c.bench_function(
        &format!(
            "Aggregate and Verifying {:?} BLS signatures",
            num_signatures
        ),
        |b| {
            b.iter(|| {
                let mut hashed_sigs = Blake2b::<U16>::new();
                for sig in sigs.iter() {
                    hashed_sigs.update(sig.to_bytes());
                }

                // First we generate the scalars
                let mut scalars = Vec::with_capacity(vks.len() * 128);
                let mut signatures = Vec::with_capacity(vks.len());
                for (index, sig) in sigs.iter().enumerate() {
                    let mut hasher = hashed_sigs.clone();
                    hasher.update(index.to_be_bytes());
                    signatures.push(sig.clone());
                    scalars.extend_from_slice(hasher.finalize().as_slice());
                }

                let vks_affine = vks
                    .iter()
                    .map(|vk| unsafe {
                        let mut projective_p2 = blst_p2::default();
                        blst_p2_from_affine(&mut projective_p2, &blst_p2_affine::from(vk.clone()));
                        projective_p2
                    })
                    .collect::<Vec<_>>();

                let sigs_affine = signatures
                    .into_iter()
                    .map(|sig| unsafe {
                        let mut projective_p1 = blst_p1::default();
                        blst_p1_from_affine(&mut projective_p1, &blst_p1_affine::from(sig));
                        projective_p1
                    })
                    .collect::<Vec<_>>();

                let grouped_vks = p2_affines::from(vks_affine.as_slice());
                let grouped_sigs = p1_affines::from(sigs_affine.as_slice());
                let p2_agg = grouped_vks.mult(&scalars, 128);
                let p1_agg = grouped_sigs.mult(&scalars, 128);

                let p2_agg = unsafe {
                    let mut affine_p2 = blst_p2_affine::default();
                    blst_p2_to_affine(&mut affine_p2, &p2_agg);
                    affine_p2
                };

                let p1_agg = unsafe {
                    let mut affine_p1 = blst_p1_affine::default();
                    blst_p1_to_affine(&mut affine_p1, &p1_agg);
                    affine_p1
                };

                let agg_sig = Signature::from(p1_agg);
                let agg_vk = PublicKey::from(p2_agg);
                let res = agg_sig.verify(false, &msg, &[], &[], &agg_vk, false);
                assert_eq!(res, BLST_SUCCESS);
            })
        },
    );
}

fn benchmark_aggregate_and_verify_64(c: &mut Criterion) {
    aggregate_and_verify(c, 64);
}
fn benchmark_aggregate_and_verify_128(c: &mut Criterion) {
    aggregate_and_verify(c, 128);
}
fn benchmark_aggregate_and_verify_256(c: &mut Criterion) {
    aggregate_and_verify(c, 256);
}
fn benchmark_aggregate_and_verify_512(c: &mut Criterion) {
    aggregate_and_verify(c, 512);
}
fn benchmark_aggregate_and_verify_1024(c: &mut Criterion) {
    aggregate_and_verify(c, 1024);
}

criterion_group!(
    benches,
    benchmark_sign,
    benchmark_verify,
    benchmark_aggregate_and_verify_64,
    benchmark_aggregate_and_verify_128,
    benchmark_aggregate_and_verify_256,
    benchmark_aggregate_and_verify_512,
    benchmark_aggregate_and_verify_1024
);
criterion_main!(benches);
