//! Sequential setup and proving timings and Criterion verification benchmarks.
//! Change `SETUP_RUNS`, `PROOF_RUNS`, and the calls in `benchmarks_topiconly`
//! and `benchmarks_topicbody` to select the workload.

mod utils;

use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use ff::Field;
use midnight_proofs::poly::kzg::params::{ParamsKZG, ParamsVerifierKZG};
use midnight_zk_stdlib as zk;
use rand::{Rng, SeedableRng, rngs::StdRng, seq::index};
use rand_core::OsRng;
use snark_stms::{
    Bls12, JubjubBase as F, MidnightCircuit, Relation,
    circuits::{
        certificate_topicbody::Certificate as TopicBodyCertificate,
        certificate_topiconly::Certificate as TopicOnlyCertificate,
    },
    merkle_tree::{MTLeaf, MerkleTree},
    schnorr_signature::{SigningKey, VerificationKey},
};
use utils::{load_srs, report_peak_ram};

// These fixed counts bound expensive work independently of Criterion settings.
// Keep both positive. Only serialized proofs and their instances are retained.
const SETUP_RUNS: usize = 1;
const PROOF_RUNS: usize = 1;

// Validate the parameters shared by both circuit variants.
fn merkle_depth(num_signers: usize, quorum: u32, num_lotteries: u32) -> u32 {
    assert!(num_signers > 0, "num_signers must be positive");
    assert!(
        quorum > 0 && quorum < num_lotteries && num_lotteries < (1 << 16),
        "require 0 < quorum < num_lotteries < 65536"
    );
    num_signers.next_power_of_two().trailing_zeros()
}

// Maximum targets make every index eligible, avoiding stake-dependent winner
// search. Registry construction and signing happen outside the timed loops.
fn create_registry(
    num_signers: usize,
    rng: &mut StdRng,
) -> (Vec<SigningKey>, Vec<MTLeaf>, MerkleTree) {
    let keys: Vec<_> = (0..num_signers)
        .map(|_| SigningKey::generate(&mut *rng))
        .collect();
    let leaves: Vec<_> = keys
        .iter()
        .map(|key| MTLeaf(VerificationKey::from(key), -F::ONE))
        .collect();
    let tree = MerkleTree::create(&leaves);
    (keys, leaves, tree)
}

// Choose distinct sorted lottery indices and a registered signer for each.
fn sample_entries(
    num_signers: usize,
    quorum: u32,
    num_lotteries: u32,
    rng: &mut StdRng,
) -> Vec<(usize, u32)> {
    let mut indices = index::sample(rng, num_lotteries as usize, quorum as usize).into_vec();
    indices.sort_unstable();
    indices
        .into_iter()
        .map(|index| (rng.gen_range(0..num_signers), index as u32))
        .collect()
}

fn benchmark_topiconly(c: &mut Criterion, num_signers: usize, quorum: u32, num_lotteries: u32) {
    let depth = merkle_depth(num_signers, quorum, num_lotteries);
    let relation = TopicOnlyCertificate::new(quorum, num_lotteries, depth);
    let mut rng = StdRng::seed_from_u64(42);
    let (keys, leaves, tree) = create_registry(num_signers, &mut rng);
    let name = format!("certificate_topiconly/n{num_signers}_q{quorum}_m{num_lotteries}");
    benchmark_certificate(c, &name, &relation, || {
        let instance = (tree.root(), F::random(&mut rng));
        let witness = sample_entries(num_signers, quorum, num_lotteries, &mut rng)
            .into_iter()
            .map(|(signer, index)| {
                let signature = keys[signer].sign(&[instance.0, instance.1], &mut rng);
                (leaves[signer], tree.get_path(signer), signature, index)
            })
            .collect();
        (instance, witness)
    });
}

fn benchmark_topicbody(c: &mut Criterion, num_signers: usize, quorum: u32, num_lotteries: u32) {
    let depth = merkle_depth(num_signers, quorum, num_lotteries);
    let relation = TopicBodyCertificate::new(quorum, num_lotteries, depth);
    let mut rng = StdRng::seed_from_u64(42);
    let (keys, leaves, tree) = create_registry(num_signers, &mut rng);
    let name = format!("certificate_topicbody/n{num_signers}_q{quorum}_m{num_lotteries}");
    benchmark_certificate(c, &name, &relation, || {
        let instance = (tree.root(), F::random(&mut rng), F::random(&mut rng));
        let witness = sample_entries(num_signers, quorum, num_lotteries, &mut rng)
            .into_iter()
            .map(|(signer, index)| {
                let topic_signature = keys[signer].sign(&[instance.0, instance.1], &mut rng);
                let body_signature =
                    keys[signer].sign(&[instance.0, instance.1, instance.2], &mut rng);
                (
                    leaves[signer],
                    tree.get_path(signer),
                    topic_signature,
                    body_signature,
                    index,
                )
            })
            .collect();
        (instance, witness)
    });
}

struct VerificationInputs<R: Relation> {
    vk: zk::MidnightVK,
    verifier_params: ParamsVerifierKZG<Bls12>,
    proofs: Vec<(R::Instance, Vec<u8>)>,
}

fn measure_setup<R: Relation>(
    name: &str,
    srs: &ParamsKZG<Bls12>,
    relation: &R,
) -> (zk::MidnightVK, zk::MidnightPK<R>) {
    eprintln!("{name}: START setup benchmark ({SETUP_RUNS} runs)");
    let mut setup_time = Duration::ZERO;
    let mut retained_keys = None;
    for run in 1..=SETUP_RUNS {
        // Release the previous keys before starting another setup.
        drop(retained_keys.take());
        eprintln!("{name}: START setup {run}/{SETUP_RUNS}");
        let start = Instant::now();
        let vk = zk::setup_vk(srs, relation);
        let pk = zk::setup_pk(relation, &vk);
        let elapsed = start.elapsed();
        setup_time += elapsed;
        println!(
            "{name}: END setup {run}/{SETUP_RUNS} = {:.6} s",
            elapsed.as_secs_f64()
        );
        retained_keys = Some((vk, pk));
    }
    let keys = retained_keys.expect("SETUP_RUNS must be positive");
    println!(
        "{name}: END setup benchmark; setup mean = {:.6} s",
        setup_time.as_secs_f64() / SETUP_RUNS as f64
    );
    keys
}

fn measure_proving<R: Relation<Error: std::fmt::Debug>>(
    name: &str,
    srs: &ParamsKZG<Bls12>,
    pk: &zk::MidnightPK<R>,
    relation: &R,
    make_certificate: &mut impl FnMut() -> (R::Instance, R::Witness),
) -> Vec<(R::Instance, Vec<u8>)> {
    eprintln!("{name}: START proving benchmark ({PROOF_RUNS} runs)");
    let mut proving_time = Duration::ZERO;
    let mut proofs = Vec::with_capacity(PROOF_RUNS);
    for run in 1..=PROOF_RUNS {
        let (instance, witness) = make_certificate();
        eprintln!("{name}: START proving {run}/{PROOF_RUNS}");
        let start = Instant::now();
        let proof =
            zk::prove::<R, blake2b_simd::State>(srs, pk, relation, &instance, witness, OsRng)
                .expect("Proof generation failed");
        let elapsed = start.elapsed();
        proving_time += elapsed;
        println!(
            "{name}: END proving {run}/{PROOF_RUNS} = {:.6} s; proof size = {} bytes",
            elapsed.as_secs_f64(),
            proof.len()
        );
        proofs.push((instance, proof));
    }
    assert!(!proofs.is_empty(), "PROOF_RUNS must be positive");
    println!(
        "{name}: END proving benchmark; prove mean = {:.6} s; verification pool = {} distinct proofs (cycled)",
        proving_time.as_secs_f64() / PROOF_RUNS as f64,
        proofs.len()
    );
    proofs
}

fn prepare_verification_inputs<R: Relation<Error: std::fmt::Debug>>(
    name: &str,
    relation: &R,
    make_certificate: &mut impl FnMut() -> (R::Instance, R::Witness),
) -> VerificationInputs<R> {
    eprintln!("{name}: sizing circuit");
    let k = MidnightCircuit::from_relation(relation, None).k();
    eprintln!("{name}: loading SRS for k={k}");
    let srs = load_srs(k);
    println!("{name}: k={k}, setup runs={SETUP_RUNS}, proof runs={PROOF_RUNS}");

    let (vk, pk) = measure_setup(name, &srs, relation);
    let proofs = measure_proving(name, &srs, &pk, relation, make_certificate);
    let verifier_params = srs.verifier_params();
    // Check every generated proof outside both setup/proving timers.
    for (instance, proof) in &proofs {
        zk::verify::<R, blake2b_simd::State>(&verifier_params, &vk, instance, None, proof)
            .expect("Generated proof did not verify");
    }

    // The proving key and full SRS are dropped when this function returns.
    VerificationInputs {
        vk,
        verifier_params,
        proofs,
    }
}

fn benchmark_certificate<R: Relation<Error: std::fmt::Debug>>(
    c: &mut Criterion,
    name: &str,
    relation: &R,
    mut make_certificate: impl FnMut() -> (R::Instance, R::Witness),
) {
    let inputs = prepare_verification_inputs(name, relation, &mut make_certificate);
    let mut next_proof = 0;
    let mut group = c.benchmark_group(name);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function("verify", move |b| {
        let proofs = inputs.proofs.as_slice();
        b.iter_batched(
            || {
                let pair = &proofs[next_proof];
                next_proof = (next_proof + 1) % proofs.len();
                pair
            },
            |(instance, proof)| {
                zk::verify::<R, blake2b_simd::State>(
                    &inputs.verifier_params,
                    &inputs.vk,
                    instance,
                    None,
                    proof,
                )
                .expect("Proof verification failed")
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
    report_peak_ram();
}

// Parameters from the Mithril paper, Table 3 (https://eprint.iacr.org/2021/916.pdf):
// adv stake 33%, phi(.50): quorum = 1129, num_lotteries = 10690
// adv stake 40%, phi(.50): quorum = 3684, num_lotteries = 34891
// adv stake 33%, phi(.55): quorum = 769,  num_lotteries = 6654
// adv stake 40%, phi(.55): quorum = 1865, num_lotteries = 16144

fn benchmarks_topiconly(c: &mut Criterion) {
    // 3,000 signers
    // benchmark_topiconly(c, 3000, 1129, 10690);
    // benchmark_topiconly(c, 3000, 3684, 34891);
    // benchmark_topiconly(c, 3000, 769, 6654);
    // benchmark_topiconly(c, 3000, 1865, 16144);

    // Additional smaller, unsafe benchmarks for quick CI runs and measurements
    // of circuit growth.
    benchmark_topiconly(c, 3000, 128, 1280);
    benchmark_topiconly(c, 3000, 256, 2560);
    benchmark_topiconly(c, 3000, 512, 5120);
    benchmark_topiconly(c, 3000, 1024, 10240);
}

fn benchmarks_topicbody(c: &mut Criterion) {
    // 3,000 signers
    // benchmark_topicbody(c, 3000, 1129, 10690);
    // benchmark_topicbody(c, 3000, 3684, 34891);
    // benchmark_topicbody(c, 3000, 769, 6654);
    // benchmark_topicbody(c, 3000, 1865, 16144);

    // Additional smaller, unsafe benchmarks for quick CI runs and measurements
    // of circuit growth.
    benchmark_topicbody(c, 3000, 128, 1280);
    benchmark_topicbody(c, 3000, 256, 2560);
    benchmark_topicbody(c, 3000, 512, 5120);
    benchmark_topicbody(c, 3000, 1024, 10240);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmarks_topiconly, benchmarks_topicbody
}
criterion_main!(benches);
