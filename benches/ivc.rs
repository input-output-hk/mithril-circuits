//! Sequential IVC setup/proving timings and Criterion full-verification timings.
//! Inner certificate setup and proving happen outside the IVC timers. Every
//! verification measures both the terminal SNARK and its public accumulator.
//!
//! Run `cargo bench --bench ivc`. Set `IVC_BENCH_SMOKE=1` for four signers and
//! quorum one; the recursive circuit and complete chain checks stay unchanged.

mod utils;

use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use ff::Field;
use midnight_proofs::poly::kzg::params::{ParamsKZG, ParamsVerifierKZG};
use midnight_zk_stdlib as zk;
use rand::{SeedableRng, rngs::StdRng};
use rand_core::OsRng;
use snark_stms::{
    Bls12, JubjubBase as F, MidnightCircuit, PoseidonState,
    circuits::{certificate_topicbody, certificate_topiconly},
    ivc_one::{
        CertificateVariant, IvcCertificate, K,
        genesis_signature::{
            Signature as GenesisSignature, SigningKey as GenesisKey, VerificationKey as GenesisVk,
        },
        io::Write,
        message::ProtocolMessage,
        proof::{IvcKeys, StepProof, initial_accumulator, prove_step, verify},
        state::{Global, State, Witness},
    },
    merkle_tree::{MTLeaf, MerkleTree},
    schnorr_signature::{SigningKey, VerificationKey},
};
use utils::{load_srs, report_peak_ram};

// Each proving run starts a fresh chain and retains only its terminal artifact.
const SETUP_RUNS: usize = 1;
const PROOF_RUNS: usize = 1;
// Includes genesis. Four steps cover genesis, epoch + 1, same epoch, epoch + 2.
const CHAIN_STEPS: usize = 4;

struct VerificationInputs {
    global: Global,
    params: ParamsVerifierKZG<Bls12>,
    proofs: Vec<StepProof>,
}

fn measure_setup(
    name: &str,
    params: &ParamsKZG<Bls12>,
    cert_vk: &zk::MidnightVK,
    variant: CertificateVariant,
) -> IvcKeys {
    let mut retained = None;
    let mut total = Duration::ZERO;
    for run in 1..=SETUP_RUNS {
        drop(retained.take());
        eprintln!("{name}: START IVC setup {run}/{SETUP_RUNS}");
        let start = Instant::now();
        let keys = IvcKeys::setup(params, cert_vk.vk(), variant).expect("IVC setup failed");
        let elapsed = start.elapsed();
        total += elapsed;
        println!(
            "{name}: END IVC setup {run}/{SETUP_RUNS} = {:.6} s",
            elapsed.as_secs_f64()
        );
        retained = Some(keys);
    }
    println!(
        "{name}: IVC setup mean = {:.6} s",
        total.as_secs_f64() / SETUP_RUNS as f64
    );
    retained.expect("SETUP_RUNS must be positive")
}

fn prepare_inputs<R: IvcCertificate>(
    name: &str,
    relation: &R,
    root: F,
    num_signers: usize,
    mut make_witness: impl FnMut(F, F, F) -> R::Witness,
) -> VerificationInputs {
    assert!(CHAIN_STEPS >= 2 && SETUP_RUNS > 0 && PROOF_RUNS > 0);
    let inner_k = MidnightCircuit::from_relation(relation, None).k();
    // All inner and recursive proofs must use the same SRS toxic-waste scalar.
    // Load one universal SRS and derive both sizes from it.
    let universal = load_srs(K.max(inner_k));
    let mut inner_srs = universal.clone();
    inner_srs.downsize(inner_k);
    let mut ivc_srs = universal;
    ivc_srs.downsize(K);

    eprintln!("{name}: preparing inner certificate keys and proofs (outside IVC timings)");
    let cert_vk = zk::setup_vk(&inner_srs, relation);
    let cert_pk = zk::setup_pk(relation, &cert_vk);
    let authority = GenesisKey::generate(&mut OsRng);
    let mut message = ProtocolMessage {
        digest: [1; 32],
        next_merkle_root: root,
        next_registry_size: u32::try_from(num_signers).expect("registry fits u32"),
        total_stake: 1_000_000,
        next_protocol_params: F::from(7),
        current_epoch: 5,
    };
    let genesis_msg = message.hash();
    let mut witnesses = Vec::with_capacity(CHAIN_STEPS);
    let mut certificate_proofs = Vec::with_capacity(CHAIN_STEPS);
    for index in 0..CHAIN_STEPS {
        message.current_epoch = if index == 0 {
            5
        } else {
            6 + ((index - 1) / 2) as u64
        };
        message.digest = [index as u8 + 1; 32];
        let msg = message.hash();
        let topic = if R::VARIANT == CertificateVariant::TopicOnly {
            msg
        } else {
            F::from(42)
        };
        let signature = if index == 0 {
            authority.sign(&[genesis_msg], &mut OsRng)
        } else {
            GenesisSignature::default()
        };
        witnesses.push(Witness::new(
            signature,
            root,
            topic,
            msg,
            message.preimage(),
        ));
        certificate_proofs.push(if index == 0 {
            Vec::new()
        } else {
            zk::prove::<R, PoseidonState<F>>(
                &inner_srs,
                &cert_pk,
                relation,
                &R::instance(root, topic, msg),
                make_witness(root, topic, msg),
                OsRng,
            )
            .expect("Inner certificate proving failed")
        });
    }
    drop(cert_pk);
    drop(inner_srs);
    println!(
        "{name}: inner k={inner_k}, IVC k={K}, chain steps={CHAIN_STEPS}, setup runs={SETUP_RUNS}, proof runs={PROOF_RUNS}"
    );
    let keys = measure_setup(name, &ivc_srs, &cert_vk, R::VARIANT);
    let global = keys.global(genesis_msg, GenesisVk::from(&authority));
    let params = ivc_srs.verifier_params();
    let mut total = Duration::ZERO;
    let mut proofs = Vec::with_capacity(PROOF_RUNS);
    for run in 1..=PROOF_RUNS {
        let mut state = State::genesis();
        let mut accumulator = initial_accumulator(&global);
        let mut previous_proof = Vec::new();
        let mut chain_time = Duration::ZERO;
        for (index, (witness, cert_proof)) in witnesses.iter().zip(&certificate_proofs).enumerate()
        {
            let terminal = index + 1 == CHAIN_STEPS;
            eprintln!(
                "{name}: START IVC proving run {run}/{PROOF_RUNS}, step {}/{CHAIN_STEPS}",
                index + 1
            );
            let start = Instant::now();
            let step = if terminal {
                prove_step::<blake2b_simd::State>(
                    &ivc_srs,
                    &keys,
                    &global,
                    &state,
                    witness,
                    cert_proof,
                    &previous_proof,
                    &accumulator,
                )
            } else {
                prove_step::<PoseidonState<F>>(
                    &ivc_srs,
                    &keys,
                    &global,
                    &state,
                    witness,
                    cert_proof,
                    &previous_proof,
                    &accumulator,
                )
            }
            .expect("IVC proving failed");
            let elapsed = start.elapsed();
            chain_time += elapsed;
            println!(
                "{name}: END IVC proving step {} = {:.6} s; proof size = {} bytes",
                index + 1,
                elapsed.as_secs_f64(),
                step.proof.len()
            );
            // Include both pairing checks in validation; keep them outside proving timers.
            if terminal {
                verify::<blake2b_simd::State>(&params, &global, &step)
                    .expect("Terminal IVC proof or accumulator is invalid");
                let mut bytes = Vec::new();
                step.accumulator
                    .write(&mut bytes, midnight_proofs::utils::SerdeFormat::RawBytes)
                    .unwrap();
                println!("{name}: terminal accumulator size = {} bytes", bytes.len());
                proofs.push(step);
            } else {
                verify::<PoseidonState<F>>(&params, &global, &step)
                    .expect("Intermediate IVC proof or accumulator is invalid");
                state = step.state;
                accumulator = step.accumulator;
                previous_proof = step.proof;
            }
        }
        total += chain_time;
        println!(
            "{name}: END IVC chain run {run}/{PROOF_RUNS} = {:.6} s",
            chain_time.as_secs_f64()
        );
    }
    println!(
        "{name}: IVC chain proving mean = {:.6} s; per-step mean = {:.6} s",
        total.as_secs_f64() / PROOF_RUNS as f64,
        total.as_secs_f64() / (PROOF_RUNS * CHAIN_STEPS) as f64
    );
    VerificationInputs {
        global,
        params,
        proofs,
    }
}

fn benchmark<R: IvcCertificate>(
    c: &mut Criterion,
    relation: R,
    num_signers: usize,
    quorum: u32,
    num_lotteries: u32,
    root: F,
    make_witness: impl FnMut(F, F, F) -> R::Witness,
) {
    let name = format!(
        "ivc_{}/n{num_signers}_q{quorum}_m{num_lotteries}_steps{CHAIN_STEPS}",
        R::VARIANT.name()
    );
    let inputs = prepare_inputs(&name, &relation, root, num_signers, make_witness);
    let mut next = 0;
    let mut group = c.benchmark_group(name);
    group.sampling_mode(SamplingMode::Flat);
    group.bench_function("verify", move |b| {
        b.iter_batched(
            || {
                let proof = &inputs.proofs[next];
                next = (next + 1) % inputs.proofs.len();
                proof
            },
            |proof| {
                verify::<blake2b_simd::State>(&inputs.params, &inputs.global, proof)
                    .expect("IVC full verification failed")
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
    // Linux reports the lifetime peak, including inner certificate preparation.
    report_peak_ram();
}

fn registry(num_signers: usize) -> (Vec<SigningKey>, Vec<MTLeaf>, MerkleTree) {
    let mut rng = StdRng::seed_from_u64(42);
    let keys: Vec<_> = (0..num_signers)
        .map(|_| SigningKey::generate(&mut rng))
        .collect();
    let leaves: Vec<_> = keys
        .iter()
        .map(|key| MTLeaf(VerificationKey::from(key), -F::ONE))
        .collect();
    let tree = MerkleTree::create(&leaves);
    (keys, leaves, tree)
}

fn workloads() -> Vec<(usize, u32, u32)> {
    if std::env::var("IVC_BENCH_SMOKE").as_deref() == Ok("1") {
        vec![(4, 1, 10)]
    } else {
        vec![
            (3000, 128, 1280),
            (3000, 256, 2560),
            (3000, 512, 5120),
            (3000, 1024, 10240),
        ]
    }
}

fn benchmarks_topiconly(c: &mut Criterion) {
    for (n, q, m) in workloads() {
        let depth = n.next_power_of_two().trailing_zeros();
        let (keys, leaves, tree) = registry(n);
        benchmark(
            c,
            certificate_topiconly::Certificate::new(q, m, depth),
            n,
            q,
            m,
            tree.root(),
            |root, topic, _| {
                (0..q)
                    .map(|index| {
                        let signer = index as usize % n;
                        (
                            leaves[signer],
                            tree.get_path(signer),
                            keys[signer].sign(&[root, topic], &mut OsRng),
                            index,
                        )
                    })
                    .collect()
            },
        );
    }
}

fn benchmarks_topicbody(c: &mut Criterion) {
    for (n, q, m) in workloads() {
        let depth = n.next_power_of_two().trailing_zeros();
        let (keys, leaves, tree) = registry(n);
        benchmark(
            c,
            certificate_topicbody::Certificate::new(q, m, depth),
            n,
            q,
            m,
            tree.root(),
            |root, topic, msg| {
                (0..q)
                    .map(|index| {
                        let signer = index as usize % n;
                        (
                            leaves[signer],
                            tree.get_path(signer),
                            keys[signer].sign(&[root, topic], &mut OsRng),
                            keys[signer].sign(&[root, topic, msg], &mut OsRng),
                            index,
                        )
                    })
                    .collect()
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmarks_topiconly, benchmarks_topicbody
}
criterion_main!(benches);
