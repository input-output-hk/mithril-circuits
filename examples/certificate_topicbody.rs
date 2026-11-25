//! Generate and verify a certificate proof with topic and body signatures.
//! Run with `cargo run --release --example certificate_topicbody`.

mod common;

use std::{error::Error, time::Instant};

use midnight_zk_stdlib as zk;
use rand_core::OsRng;
use snark_stms::{JubjubBase as F, MidnightCircuit, circuits::certificate_topicbody::Certificate};

// Change these constants to select the workload.
const NUM_SIGNERS: usize = 100;
const QUORUM: u32 = 3;
const NUM_LOTTERIES: u32 = 30;

fn main() -> Result<(), Box<dyn Error>> {
    const {
        assert!(NUM_SIGNERS > 0);
        assert!(0 < QUORUM && QUORUM < NUM_LOTTERIES && NUM_LOTTERIES < (1 << 16));
    }
    let (keys, leaves, tree) = common::create_registry(NUM_SIGNERS);
    let depth = NUM_SIGNERS.next_power_of_two().trailing_zeros();
    let relation = Certificate::new(QUORUM, NUM_LOTTERIES, depth);
    let instance = (tree.root(), F::from(42), F::from(43));
    let witness = (0..QUORUM)
        .map(|index| {
            let signer = index as usize % NUM_SIGNERS;
            let topic_signature = keys[signer].sign(&[instance.0, instance.1], &mut OsRng);
            let body_signature =
                keys[signer].sign(&[instance.0, instance.1, instance.2], &mut OsRng);
            (
                leaves[signer],
                tree.get_path(signer),
                topic_signature,
                body_signature,
                index,
            )
        })
        .collect();

    println!(
        "Topic/body certificate: {NUM_SIGNERS} signers, quorum {QUORUM}, {NUM_LOTTERIES} lotteries"
    );
    println!("Sizing circuit...");
    let k = MidnightCircuit::from_relation(&relation, None).k();
    println!("Circuit size: k={k}");
    let srs = common::load_srs(k)?;

    println!("Starting setup...");
    let start = Instant::now();
    let vk = zk::setup_vk(&srs, &relation);
    let pk = zk::setup_pk(&relation, &vk);
    println!("Setup time: {:.6} s", start.elapsed().as_secs_f64());

    println!("Starting proof generation...");
    let start = Instant::now();
    let proof = zk::prove::<Certificate, blake2b_simd::State>(
        &srs, &pk, &relation, &instance, witness, OsRng,
    )?;
    println!(
        "Proof generation time: {:.6} s",
        start.elapsed().as_secs_f64()
    );
    println!("Proof size: {} bytes", proof.len());

    let verifier_params = srs.verifier_params();
    println!("Starting verification...");
    let start = Instant::now();
    zk::verify::<Certificate, blake2b_simd::State>(&verifier_params, &vk, &instance, None, &proof)?;
    println!("Verification time: {:.6} s", start.elapsed().as_secs_f64());
    println!("Proof verified successfully.");
    Ok(())
}
