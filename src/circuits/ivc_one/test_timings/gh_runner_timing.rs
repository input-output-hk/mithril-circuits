use ff::Field;
use midnight_proofs::{dev::MockProver, plonk::VerifyingKey, utils::SerdeFormat};
use std::{fs::File, io::BufReader, time::Instant};

use crate::{
    Accumulator, AssignedAccumulator, Bls12, BlstrsEmulation, IVC_ONE_NAME, Instantiable,
    JubjubBase, KZGCommitmentScheme,
    ivc_one::{
        circuit::IvcCircuit,
        io::Read as IvcRead,
        state::{Global, State, Witness, fixed_bases_and_names, trivial_acc},
    },
    keygen_pk,
    protocol_message::{ProtocolMessage, ProtocolMessagePartKey},
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

/// Single test that measures all CI-tier operations end-to-end.
/// Covers: setup, VK stability, base case MockProver (valid + invalid),
/// and recursive step MockProver (valid + invalid).
///
/// Run with:
///   cargo test --release test_timings::gh_runner_timing::ci_tier_timings -- --include-ignored --nocapture
#[test]
#[ignore]
fn ci_tier_timings() {
    println!("\n========================================");
    println!("  CI-TIER TIMING: shared setup");
    println!("========================================\n");

    println!("[*] Loading KZG parameters (SRS pair)...");
    let t = Instant::now();
    let (cert_srs, ivc_srs) = open_srs_pair();
    println!(
        "[+] open_srs_pair:        {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Loading KZG parameters (K={})...", K);
    let t = Instant::now();
    let srs = open_params(K);
    println!(
        "[+] open_params:          {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Building shared setup (signers, merkle tree, genesis cert)...");
    let t = Instant::now();
    let setup = build_shared_setup();
    println!(
        "[+] build_shared_setup:   {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Generating cert and IVC verifying keys...");
    let t = Instant::now();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);
    println!(
        "[+] setup_keys:           {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    println!("========================================");
    println!("  CI-TIER TIMING: VK stability");
    println!("========================================\n");

    println!("[*] Comparing recomputed VK against stored reference...");
    let t = Instant::now();
    let file = File::open(protocol_data_path()).expect("protocol_data.bin not found");
    let mut r = BufReader::new(file);
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
        "VK mismatch"
    );
    println!(
        "[+] vk_stability:         {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("========================================");
    println!("  CI-TIER TIMING: IVC base case (valid)");
    println!("========================================\n");

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

    let base_acc = trivial_acc(&keys.combined_fixed_base_names);

    let base_circuit = IvcCircuit::new(
        global.clone(),
        State::genesis(),
        Witness::new(
            setup.genesis_sig.clone(),
            JubjubBase::ZERO,
            JubjubBase::ZERO,
            genesis_preimage.clone().try_into().unwrap(),
        ),
        vec![],
        vec![],
        base_acc.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    let genesis_next_state = State::new(
        JubjubBase::ONE,
        setup.genesis_msg,
        JubjubBase::ZERO,
        setup.genesis_next_merkle_root,
        JubjubBase::ZERO,
        setup.genesis_next_protocol_params,
        JubjubBase::from(5u64),
    );

    let base_pi = [
        global.as_public_input(),
        genesis_next_state.as_public_input(),
        AssignedAccumulator::as_public_input(&base_acc),
    ]
    .concat();

    println!("[*] Running MockProver on genesis circuit (K={})...", K);
    let t = Instant::now();
    let prover =
        MockProver::run(K, &base_circuit, vec![vec![], base_pi]).expect("MockProver::run failed");
    println!(
        "[+] base_mock_run:        {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Verifying base case constraints...");
    let t = Instant::now();
    prover.verify().expect("IVC base case constraints violated");
    println!(
        "[+] base_mock_verify:     {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("========================================");
    println!("  CI-TIER TIMING: IVC base case (invalid)");
    println!("========================================\n");

    let base_circuit_neg = IvcCircuit::new(
        global.clone(),
        State::genesis(),
        Witness::new(
            setup.genesis_sig.clone(),
            JubjubBase::ZERO,
            JubjubBase::ZERO,
            genesis_preimage.try_into().unwrap(),
        ),
        vec![],
        vec![],
        base_acc.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    let tampered_state = State::new(
        JubjubBase::ONE,
        setup.genesis_msg,
        JubjubBase::ZERO,
        setup.genesis_next_merkle_root,
        JubjubBase::ZERO,
        setup.genesis_next_protocol_params,
        JubjubBase::from(999u64),
    );

    let tampered_pi = [
        global.as_public_input(),
        tampered_state.as_public_input(),
        AssignedAccumulator::as_public_input(&base_acc),
    ]
    .concat();

    println!("[*] Running MockProver with tampered public inputs...");
    let t = Instant::now();
    let prover = MockProver::run(K, &base_circuit_neg, vec![vec![], tampered_pi])
        .expect("MockProver::run failed");
    assert!(prover.verify().is_err(), "should reject tampered inputs");
    println!(
        "[+] base_mock_invalid:    {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("========================================");
    println!("  CI-TIER TIMING: IVC recursive step (valid)");
    println!("========================================\n");

    println!("[*] Loading chain state from asset...");
    let t = Instant::now();
    let (state, ivc_proof, acc) = load_chain_state(&chain_state_path());
    println!(
        "[+] load_chain_state:     {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Building new certificate (K={})...", super::K_INNER);
    let t = Instant::now();
    let new_cert = build_new_cert(&setup, &keys, &cert_srs, &state);
    println!(
        "[+] build_new_cert:       {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Computing next accumulator...");
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
    println!(
        "[+] compute_next_acc:     {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Building recursive IVC circuit...");
    let t = Instant::now();
    let (circuit, public_inputs) = build_ivc_circuit(
        &global,
        &state,
        new_cert,
        ivc_proof.clone(),
        &acc,
        &next_acc,
        &keys,
    );
    println!(
        "[+] build_ivc_circuit:    {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Running MockProver on recursive circuit (K={})...", K);
    let t = Instant::now();
    let prover =
        MockProver::run(K, &circuit, vec![vec![], public_inputs]).expect("MockProver::run failed");
    println!(
        "[+] recur_mock_run:       {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Verifying recursive step constraints...");
    let t = Instant::now();
    prover
        .verify()
        .expect("IVC recursive step constraints violated");
    println!(
        "[+] recur_mock_verify:    {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("========================================");
    println!("  CI-TIER TIMING: IVC recursive step (invalid)");
    println!("========================================\n");

    let new_cert2 = build_new_cert(&setup, &keys, &cert_srs, &state);
    let next_acc2 = compute_next_acc(
        &ivc_srs,
        &srs,
        &keys,
        &global,
        &state,
        &acc,
        &ivc_proof,
        new_cert2.cert_acc.clone(),
    );

    let mut corrupted_proof = ivc_proof;
    if let Some(byte) = corrupted_proof.get_mut(10) {
        *byte ^= 0xFF;
    }

    let (circuit_neg, pi_neg) = build_ivc_circuit(
        &global,
        &state,
        new_cert2,
        corrupted_proof,
        &acc,
        &next_acc2,
        &keys,
    );

    println!("[*] Running MockProver with corrupted proof bytes...");
    let t = Instant::now();
    let prover =
        MockProver::run(K, &circuit_neg, vec![vec![], pi_neg]).expect("MockProver::run failed");
    assert!(prover.verify().is_err(), "should reject corrupted proof");
    println!(
        "[+] recur_mock_invalid:   {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("========================================");
    println!("  CI-TIER TIMING: end-to-end verification");
    println!("========================================\n");

    let proto_file = File::open(protocol_data_path()).expect("protocol_data.bin not found");
    let mut r = BufReader::new(proto_file);
    let global_fes: Vec<JubjubBase> = (0..5).map(|_| read_fe(&mut r)).collect();
    let stored_vk = VerifyingKey::<JubjubBase, KZGCommitmentScheme<Bls12>>::read::<_, IvcCircuit>(
        &mut r,
        SerdeFormat::RawBytesUnchecked,
        (),
    )
    .expect("failed to read stored self_vk");
    let combined_fixed_bases = read_combined_fixed_bases(&mut r);
    let (self_fixed_bases, _) = fixed_bases_and_names(IVC_ONE_NAME, &stored_vk);

    let aggr_file = File::open(aggr_result_path()).expect("aggr_result.bin not found");
    let mut r = BufReader::new(aggr_file);
    let stored_proof = read_proof(&mut r);
    let stored_acc = Accumulator::<BlstrsEmulation>::read(&mut r, SerdeFormat::RawBytesUnchecked)
        .expect("failed to read stored accumulator");
    let stored_next_state = read_state(&mut r);

    let verifier_pi = [
        global_fes.as_slice(),
        &stored_next_state.as_public_input(),
        &AssignedAccumulator::as_public_input(&stored_acc),
    ]
    .concat();

    println!("[*] Verifying stored Blake2b IVC proof...");
    let t = Instant::now();
    let _proof_acc = verify_ivc_blake2(
        &ivc_srs,
        &stored_vk,
        &self_fixed_bases,
        &stored_proof,
        &verifier_pi,
    );
    println!(
        "[+] verify_ivc_blake2:    {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Checking stored accumulator against combined fixed bases...");
    let t = Instant::now();
    assert!(
        stored_acc.check(&srs.s_g2().into(), &combined_fixed_bases),
        "stored accumulator check failed"
    );
    println!(
        "[+] acc_check:            {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("========================================");
    println!("  CI-TIER TIMING: complete");
    println!("========================================");
}

/// Single test that measures all slow-tier (full prover) operations end-to-end.
/// Covers: aggregator proving pipeline and verifier pipeline.
///
/// Run with:
///   cargo test --release test_timings::gh_runner_timing::slow_tier_timings -- --include-ignored --nocapture
#[test]
#[ignore]
fn slow_tier_timings() {
    println!("\n========================================");
    println!("  SLOW-TIER TIMING: shared setup");
    println!("========================================\n");

    println!("[*] Loading KZG parameters...");
    let t = Instant::now();
    let (cert_srs, ivc_srs) = open_srs_pair();
    let srs = open_params(K.max(K_INNER));
    println!(
        "[+] load_srs:             {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Building shared setup...");
    let t = Instant::now();
    let setup = build_shared_setup();
    println!(
        "[+] build_shared_setup:   {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Generating cert and IVC verifying keys...");
    let t = Instant::now();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);
    println!(
        "[+] setup_keys:           {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    println!("========================================");
    println!("  SLOW-TIER TIMING: aggregator proving");
    println!("========================================\n");

    println!("[*] Generating IVC proving key...");
    let t = Instant::now();
    let self_pk = keygen_pk(
        keys.self_vk.clone(),
        &IvcCircuit::unknown(keys.cert_vk.vk()),
    )
    .unwrap();
    println!(
        "[+] keygen_pk:            {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    let (state, ivc_proof, acc) = load_chain_state(&chain_state_path());

    println!("[*] Building new certificate (K={})...", K_INNER);
    let t = Instant::now();
    let new_cert = build_new_cert(&setup, &keys, &cert_srs, &state);
    println!(
        "[+] build_new_cert:       {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Computing next accumulator...");
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
    println!(
        "[+] compute_next_acc:     {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Building recursive IVC circuit...");
    let t = Instant::now();
    let (circuit, public_inputs) =
        build_ivc_circuit(&global, &state, new_cert, ivc_proof, &acc, &next_acc, &keys);
    println!(
        "[+] build_ivc_circuit:    {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Generating Blake2b IVC proof (K={})...", K);
    let t = Instant::now();
    let final_proof = prove_ivc_blake2(&ivc_srs, &self_pk, &circuit, &public_inputs);
    println!(
        "[+] prove_ivc_blake2:     {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("========================================");
    println!("  SLOW-TIER TIMING: verifier");
    println!("========================================\n");

    println!("[*] Verifying Blake2b IVC proof...");
    let t = Instant::now();
    let _proof_acc = verify_ivc_blake2(
        &ivc_srs,
        &keys.self_vk,
        &keys.self_fixed_bases,
        &final_proof,
        &public_inputs,
    );
    println!(
        "[+] verify_ivc_blake2:    {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("[*] Checking accumulator against combined fixed bases...");
    let t = Instant::now();
    assert!(
        next_acc.check(&srs.s_g2().into(), &keys.combined_fixed_bases),
        "next_acc check failed"
    );
    println!(
        "[+] acc_check:            {:.3}s\n",
        t.elapsed().as_secs_f64()
    );

    println!("========================================");
    println!("  SLOW-TIER TIMING: complete");
    println!("========================================");
}
