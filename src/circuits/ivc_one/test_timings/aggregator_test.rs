use midnight_proofs::{plonk::VerifyingKey, utils::SerdeFormat};
use std::{fs::File, io::BufReader, time::Instant};

use crate::{
    Accumulator, AssignedAccumulator, Bls12, BlstrsEmulation, IVC_ONE_NAME, Instantiable,
    JubjubBase, KZGCommitmentScheme,
    ivc_one::{
        circuit::IvcCircuit,
        io::Read as IvcRead,
        state::{Global, fixed_bases_and_names},
    },
    keygen_pk,
};

use super::{
    K, K_INNER,
    data_generators::{
        aggr_result_path, build_ivc_circuit, build_new_cert, build_shared_setup, chain_state_path,
        compute_next_acc, load_chain_state, protocol_data_path,
    },
    helpers::{
        open_params, open_srs_pair, prove_ivc_blake2, read_combined_fixed_bases, read_fe,
        read_proof, read_state, setup_keys, verify_ivc_blake2,
    },
};

/// Simulate the aggregator extending an existing IVC chain by one step.
/// Proves with Blake2b and saves the result for the separate verification test.
///
/// Prerequisites (run before this test):
///   cargo test --release test_timings::data_generators::generate_chain_state -- --include-ignored --nocapture
///
/// Run with:
///   cargo test --release test_timings::aggregator_test::aggregator_test -- --include-ignored --nocapture
#[test]
#[ignore]
fn aggregator_test() {
    // Setup
    let setup = build_shared_setup();
    let (cert_srs, ivc_srs) = open_srs_pair();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);
    let srs = open_params(K.max(K_INNER));

    let t = Instant::now();
    let self_pk = keygen_pk(
        keys.self_vk.clone(),
        &IvcCircuit::unknown(keys.cert_vk.vk()),
    )
    .unwrap();
    println!("keygen_pk:         {:.3}s", t.elapsed().as_secs_f64());

    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    let (state, ivc_proof, acc) = load_chain_state(&chain_state_path());

    let t = Instant::now();
    let new_cert = build_new_cert(&setup, &keys, &cert_srs, &state);
    println!("build_new_cert:    {:.3}s", t.elapsed().as_secs_f64());

    // Step 3: Compute next accumulator
    let t = Instant::now();
    let next_acc = compute_next_acc(
        &ivc_srs,
        &srs,
        &keys,
        &global,
        &state,
        &acc,
        &ivc_proof,
        new_cert.cert_acc.clone(),
    );
    println!("compute_next_acc:  {:.3}s", t.elapsed().as_secs_f64());

    // Step 4: Build IVC circuit
    let t = Instant::now();
    let (circuit, public_inputs) =
        build_ivc_circuit(&global, &state, new_cert, ivc_proof, &acc, &next_acc, &keys);
    println!("build_ivc_circuit: {:.3}s", t.elapsed().as_secs_f64());

    // Step 5: Prove with Blake2b
    let t = Instant::now();
    let _final_proof = prove_ivc_blake2(&ivc_srs, &self_pk, &circuit, &public_inputs);
    println!("prove_ivc_blake2:  {:.3}s", t.elapsed().as_secs_f64());
}

/// Verify the aggregator's Blake2b IVC proof using only data a verifier would have.
///
/// Prerequisites (run before this test):
///   cargo test --release test_timings::data_generators::generate_protocol_data -- --include-ignored --nocapture
///   cargo test --release test_timings::data_generators::generate_aggr_result -- --include-ignored --nocapture
///
/// Run with:
///   cargo test --release test_timings::aggregator_test::verify_aggregator_test -- --include-ignored --nocapture
#[test]
#[ignore]
fn verify_aggregator_test() {
    // Setup (not timed)
    let srs = open_params(K.max(K_INNER));
    let ivc_srs = {
        let mut s = srs.clone();
        if K < K.max(K_INNER) {
            s.downsize(K);
        }
        s
    };

    let proto_file = File::open(protocol_data_path())
        .expect("protocol_data.bin not found — run generate_protocol_data first");
    let mut r = BufReader::new(proto_file);

    let global_fes: Vec<JubjubBase> = (0..5).map(|_| read_fe(&mut r)).collect();
    let self_vk = VerifyingKey::<JubjubBase, KZGCommitmentScheme<Bls12>>::read::<_, IvcCircuit>(
        &mut r,
        SerdeFormat::RawBytesUnchecked,
        (),
    )
    .expect("failed to read self_vk");
    let combined_fixed_bases = read_combined_fixed_bases(&mut r);
    let (self_fixed_bases, _) = fixed_bases_and_names(IVC_ONE_NAME, &self_vk);

    let aggr_file = File::open(aggr_result_path())
        .expect("aggr_result.bin not found — run generate_aggr_result first");
    let mut r = BufReader::new(aggr_file);

    let final_proof = read_proof(&mut r);
    let next_acc = Accumulator::<BlstrsEmulation>::read(&mut r, SerdeFormat::RawBytesUnchecked)
        .expect("failed to read next_acc");
    let ivc_next_state = read_state(&mut r);

    let public_inputs = [
        global_fes.as_slice(),
        &ivc_next_state.as_public_input(),
        &AssignedAccumulator::as_public_input(&next_acc),
    ]
    .concat();

    // Verify Blake2b IVC proof
    let t = Instant::now();
    let _proof_acc = verify_ivc_blake2(
        &ivc_srs,
        &self_vk,
        &self_fixed_bases,
        &final_proof,
        &public_inputs,
    );
    println!("verify_ivc_blake2: {:.3}s", t.elapsed().as_secs_f64());

    // Check accumulator
    let t = Instant::now();
    assert!(
        next_acc.check(&srs.s_g2().into(), &combined_fixed_bases),
        "next_acc check failed"
    );
    println!("acc_check:         {:.3}s", t.elapsed().as_secs_f64());
}
