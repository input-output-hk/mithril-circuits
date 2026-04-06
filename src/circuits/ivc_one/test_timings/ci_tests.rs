use ff::Field;
use midnight_proofs::{dev::MockProver, plonk::VerifyingKey, utils::SerdeFormat};
use std::{fs::File, io::BufReader, time::Instant};

use crate::{
    AssignedAccumulator, Bls12, Instantiable, JubjubBase, KZGCommitmentScheme,
    ivc_one::{
        circuit::IvcCircuit,
        state::{Global, State, Witness, trivial_acc},
    },
    protocol_message::{ProtocolMessage, ProtocolMessagePartKey},
};

use super::{
    K,
    data_generators::{
        build_ivc_circuit, build_new_cert, build_shared_setup, chain_state_path, compute_next_acc,
        load_chain_state, protocol_data_path,
    },
    helpers::{open_params, open_srs_pair, read_fe, setup_keys},
};

/// Measure the time spent on each setup procedure used across the CI tests.
///
/// Run with:
///   cargo test --release test_timings::ci_tests::setup_timings -- --include-ignored --nocapture
#[test]
#[ignore]
fn setup_timings() {
    let t = Instant::now();
    let (cert_srs, ivc_srs) = open_srs_pair();
    println!("open_srs_pair:      {:.3}s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let _srs = open_params(K);
    println!("open_params:        {:.3}s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let setup = build_shared_setup();
    println!("build_shared_setup: {:.3}s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);
    println!("setup_keys:         {:.3}s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let (state, _ivc_proof, _acc) = load_chain_state(&chain_state_path());
    println!("load_chain_state:   {:.3}s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let _new_cert = build_new_cert(&setup, &keys, &cert_srs, &state);
    println!("build_new_cert:     {:.3}s", t.elapsed().as_secs_f64());
}

/// Recompute the IVC verifying key from the current circuit and assert it matches
/// the reference key stored in protocol_data.bin.
///
/// Run with:
///   cargo test --release test_timings::ci_tests::vk_stability -- --nocapture
#[test]
fn vk_stability() {
    let (cert_srs, ivc_srs) = open_srs_pair();
    let setup = build_shared_setup();

    let t = Instant::now();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);
    println!("setup_keys:         {:.3}s", t.elapsed().as_secs_f64());

    let file = File::open(protocol_data_path())
        .expect("protocol_data.bin not found, run generate_protocol_data first");
    let mut r = BufReader::new(file);

    // Skip the 5 global field elements
    for _ in 0..5 {
        read_fe(&mut r);
    }

    let stored_vk = VerifyingKey::<JubjubBase, KZGCommitmentScheme<Bls12>>::read::<_, IvcCircuit>(
        &mut r,
        SerdeFormat::RawBytesUnchecked,
        (),
    )
    .expect("failed to read stored self_vk");

    assert_eq!(
        keys.self_vk.transcript_repr(),
        stored_vk.transcript_repr(),
        "VK mismatch: the circuit structure has changed. Regenerate test assets."
    );
}

/// Verify that the genesis (base case) IVC circuit satisfies all constraints
/// using MockProver. No stored assets needed.
///
/// Run with:
///   cargo test --release test_timings::ci_tests::ivc_base_case_valid -- --nocapture
#[test]
fn ivc_base_case_valid() {
    let (cert_srs, ivc_srs) = open_srs_pair();
    let setup = build_shared_setup();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);

    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    // Genesis state: all zeros
    let state = State::genesis();

    // Trivial accumulator for the combined fixed bases
    let acc = trivial_acc(&keys.combined_fixed_base_names);
    let next_acc = acc.clone();

    // Reconstruct the genesis preimage (same as build_shared_setup)
    let genesis_preimage = {
        let mut pm = ProtocolMessage::new();
        pm.set_message_part(ProtocolMessagePartKey::Digest, vec![2u8; 32]);
        pm.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            setup.avk.clone().into(),
        );
        pm.set_message_part(
            ProtocolMessagePartKey::NextProtocolParameters,
            setup.genesis_next_protocol_params.to_bytes_le().to_vec(),
        );
        pm.set_message_part(
            ProtocolMessagePartKey::CurrentEpoch,
            5u64.to_le_bytes().into(),
        );
        pm.get_preimage()
    };

    let witness = Witness::new(
        setup.genesis_sig.clone(),
        JubjubBase::ZERO,
        JubjubBase::ZERO,
        genesis_preimage.try_into().unwrap(),
    );

    let circuit = IvcCircuit::new(
        global.clone(),
        state,
        witness,
        vec![], // no cert proof at genesis
        vec![], // no prior IVC proof at genesis
        acc,
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    // Genesis next state (step 0 output)
    let genesis_next_state = State::new(
        JubjubBase::ONE,
        setup.genesis_msg,
        JubjubBase::ZERO,
        setup.genesis_next_merkle_root,
        JubjubBase::ZERO,
        setup.genesis_next_protocol_params,
        JubjubBase::from(5u64),
    );

    let public_inputs = [
        global.as_public_input(),
        genesis_next_state.as_public_input(),
        AssignedAccumulator::as_public_input(&next_acc),
    ]
    .concat();

    let t = Instant::now();
    let prover =
        MockProver::run(K, &circuit, vec![vec![], public_inputs]).expect("MockProver::run failed");
    println!("mock_prover_run:    {:.3}s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    prover.verify().expect("IVC base case constraints violated");
    println!("mock_prover_verify: {:.3}s", t.elapsed().as_secs_f64());
}

/// Verify that the genesis IVC circuit rejects a wrong public input.
///
/// Run with:
///   cargo test --release test_timings::ci_tests::ivc_base_case_invalid -- --nocapture
#[test]
fn ivc_base_case_invalid() {
    let (cert_srs, ivc_srs) = open_srs_pair();
    let setup = build_shared_setup();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);

    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    let state = State::genesis();
    let acc = trivial_acc(&keys.combined_fixed_base_names);
    let next_acc = acc.clone();

    let genesis_preimage = {
        let mut pm = ProtocolMessage::new();
        pm.set_message_part(ProtocolMessagePartKey::Digest, vec![2u8; 32]);
        pm.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            setup.avk.clone().into(),
        );
        pm.set_message_part(
            ProtocolMessagePartKey::NextProtocolParameters,
            setup.genesis_next_protocol_params.to_bytes_le().to_vec(),
        );
        pm.set_message_part(
            ProtocolMessagePartKey::CurrentEpoch,
            5u64.to_le_bytes().into(),
        );
        pm.get_preimage()
    };

    let witness = Witness::new(
        setup.genesis_sig.clone(),
        JubjubBase::ZERO,
        JubjubBase::ZERO,
        genesis_preimage.try_into().unwrap(),
    );

    let circuit = IvcCircuit::new(
        global.clone(),
        state,
        witness,
        vec![],
        vec![],
        acc,
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    // Tamper with the next state: wrong epoch
    let tampered_state = State::new(
        JubjubBase::ONE,
        setup.genesis_msg,
        JubjubBase::ZERO,
        setup.genesis_next_merkle_root,
        JubjubBase::ZERO,
        setup.genesis_next_protocol_params,
        JubjubBase::from(999u64), // wrong epoch
    );

    let public_inputs = [
        global.as_public_input(),
        tampered_state.as_public_input(),
        AssignedAccumulator::as_public_input(&next_acc),
    ]
    .concat();

    let prover =
        MockProver::run(K, &circuit, vec![vec![], public_inputs]).expect("MockProver::run failed");

    assert!(
        prover.verify().is_err(),
        "MockProver should reject tampered public inputs"
    );
}

/// Verify that the recursive step of the IVC circuit satisfies all constraints
/// using MockProver. Loads prior chain state from chain_state.bin.
///
/// Run with:
///   cargo test --release test_timings::ci_tests::ivc_recursive_step_valid -- --nocapture
#[test]
fn ivc_recursive_step_valid() {
    let (cert_srs, ivc_srs) = open_srs_pair();
    let srs = open_params(K);
    let setup = build_shared_setup();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);

    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    let (state, ivc_proof, acc) = load_chain_state(&chain_state_path());

    let t = Instant::now();
    let new_cert = build_new_cert(&setup, &keys, &cert_srs, &state);
    println!("build_new_cert:     {:.3}s", t.elapsed().as_secs_f64());

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
    println!("compute_next_acc:   {:.3}s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let (circuit, public_inputs) =
        build_ivc_circuit(&global, &state, new_cert, ivc_proof, &acc, &next_acc, &keys);
    println!("build_ivc_circuit:  {:.3}s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let prover =
        MockProver::run(K, &circuit, vec![vec![], public_inputs]).expect("MockProver::run failed");
    println!("mock_prover_run:    {:.3}s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    prover
        .verify()
        .expect("IVC recursive step constraints violated");
    println!("mock_prover_verify: {:.3}s", t.elapsed().as_secs_f64());
}

/// Verify that the recursive step IVC circuit rejects corrupted prior proof bytes.
///
/// Run with:
///   cargo test --release test_timings::ci_tests::ivc_recursive_step_invalid -- --nocapture
#[test]
fn ivc_recursive_step_invalid() {
    let (cert_srs, ivc_srs) = open_srs_pair();
    let srs = open_params(K);
    let setup = build_shared_setup();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);

    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    let (state, ivc_proof, acc) = load_chain_state(&chain_state_path());
    let new_cert = build_new_cert(&setup, &keys, &cert_srs, &state);
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

    // Corrupt the prior IVC proof bytes
    let mut corrupted_proof = ivc_proof;
    if let Some(byte) = corrupted_proof.get_mut(10) {
        *byte ^= 0xFF;
    }

    let (circuit, public_inputs) = build_ivc_circuit(
        &global,
        &state,
        new_cert,
        corrupted_proof,
        &acc,
        &next_acc,
        &keys,
    );

    let prover =
        MockProver::run(K, &circuit, vec![vec![], public_inputs]).expect("MockProver::run failed");

    assert!(
        prover.verify().is_err(),
        "MockProver should reject corrupted prior proof bytes"
    );
}
