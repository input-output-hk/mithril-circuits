use ff::Field;
use group::Group;
use midnight_proofs::utils::SerdeFormat;
use midnight_proofs::utils::helpers::ProcessedSerdeObject;
use midnight_zk_stdlib as zk_lib;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};
use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Write as IoWrite},
    path::PathBuf,
};

use crate::{
    Accumulator, AssignedAccumulator, Bls12, BlstrsEmulation, CERT_VK_NAME, CircuitTranscript,
    Instantiable, JubjubBase, KZGCommitmentScheme, ParamsKZG, PoseidonState, Relation, Transcript,
    certificate::Certificate,
    ivc_one::{
        circuit::IvcCircuit,
        io::{Read as IvcRead, Write as IvcWrite},
        state::{Global, State, Witness, fixed_bases_and_names, trivial_acc},
    },
    keygen_pk,
    merkle_tree::{MTLeaf, MerkleTree},
    prepare,
    protocol_message::{AggregateVerificationKey, ProtocolMessage, ProtocolMessagePartKey},
    schnorr_signature::{
        Signature, SigningKey as SchnorrSigningKey, VerificationKey as SchnorrVerificationKey,
    },
    unique_signature::{SigningKey, VerificationKey},
    utils::jubjub_base_from_le_bytes,
};

use super::{
    C, K, K_INNER,
    helpers::{
        KeysData, open_params, open_srs_pair, prove_ivc_blake2, prove_ivc_poseidon, read_fe,
        read_proof, read_state, setup_keys, verify_ivc_poseidon,
    },
};

/// Number of certificates in the initial chain (before the aggregator adds one more).
const CHAIN_LENGTH: usize = 3;
/// Quorum used for all certificates.
const QUORUM: u32 = 2;

/// Returning the path to the chain state file
pub(super) fn chain_state_path() -> PathBuf {
    PathBuf::from("src/circuits/ivc_one/test_timings/assets/chain_state.bin")
}

/// Returning the path to the new cert file
pub(super) fn new_cert_path() -> PathBuf {
    PathBuf::from("src/circuits/ivc_one/test_timings/assets/new_cert.bin")
}

/// Returning the path to the protocol data file
pub(super) fn protocol_data_path() -> PathBuf {
    PathBuf::from("src/circuits/ivc_one/test_timings/assets/protocol_data.bin")
}

/// Returning the path to the aggregator result file
pub(super) fn aggr_result_path() -> PathBuf {
    PathBuf::from("src/circuits/ivc_one/test_timings/assets/aggr_result.bin")
}

/// Shared setup for both chain state generation and new cert generation:
/// signers, merkle tree, genesis cert, etc.
pub(super) struct SharedSetup {
    pub(super) cert_relation: Certificate,
    pub(super) genesis_vk: SchnorrVerificationKey,
    pub(super) genesis_msg: JubjubBase,
    pub(super) genesis_sig: Signature,
    pub(super) merkle_tree: MerkleTree,
    pub(super) leaves: Vec<MTLeaf>,
    pub(super) sks: Vec<SigningKey>,
    pub(super) avk: AggregateVerificationKey,
    pub(super) genesis_next_merkle_root: JubjubBase,
    pub(super) genesis_next_protocol_params: JubjubBase,
}

/// Build deterministic shared setup: signers, merkle tree, genesis cert.
/// Uses `ChaCha20Rng::seed_from_u64(42)` for reproducibility.
pub(super) fn build_shared_setup() -> SharedSetup {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let num_signers: usize = 3000;
    let depth = num_signers.next_power_of_two().trailing_zeros();
    let num_lotteries = QUORUM * 10;
    let total_stake = 1_000_000u64;

    let cert_relation = Certificate::new(QUORUM, num_lotteries, depth);

    let mut sks = Vec::with_capacity(num_signers);
    let mut leaves = Vec::with_capacity(num_signers);
    for _ in 0..num_signers {
        let sk = SigningKey::generate(&mut rng);
        let vk = VerificationKey::from(&sk);
        leaves.push(MTLeaf(vk, -JubjubBase::ONE));
        sks.push(sk);
    }
    let merkle_tree = MerkleTree::create(&leaves);
    let avk = AggregateVerificationKey::new(merkle_tree.to_merkle_tree_commitment(), total_stake);
    let genesis_next_merkle_root = merkle_tree.root();
    let genesis_next_protocol_params = JubjubBase::from(7u64);

    let genesis_epoch = 5u64;
    let genesis_sk = SchnorrSigningKey::generate(&mut rng);
    let genesis_vk = SchnorrVerificationKey::from(&genesis_sk);

    let (genesis_msg, _genesis_preimage) = {
        let mut pm = ProtocolMessage::new();
        pm.set_message_part(ProtocolMessagePartKey::Digest, vec![2u8; 32]);
        pm.set_message_part(
            ProtocolMessagePartKey::NextAggregateVerificationKey,
            avk.clone().into(),
        );
        pm.set_message_part(
            ProtocolMessagePartKey::NextProtocolParameters,
            genesis_next_protocol_params.to_bytes_le().to_vec(),
        );
        pm.set_message_part(
            ProtocolMessagePartKey::CurrentEpoch,
            genesis_epoch.to_le_bytes().into(),
        );
        let preimage = pm.get_preimage();
        let msg = pm.compute_hash();
        (jubjub_base_from_le_bytes(&msg), preimage)
    };
    let genesis_sig = genesis_sk.sign(&[genesis_msg], &mut rng);
    genesis_sig.verify(&[genesis_msg], &genesis_vk).unwrap();

    SharedSetup {
        cert_relation,
        genesis_vk,
        genesis_msg,
        genesis_sig,
        merkle_tree,
        leaves,
        sks,
        avk,
        genesis_next_merkle_root,
        genesis_next_protocol_params,
    }
}

/// Output type and builder for new cert
pub(super) struct NewCertData {
    pub(super) cert_proof: Vec<u8>,
    pub(super) cert_acc: Accumulator<BlstrsEmulation>,
    pub(super) ivc_next_state: State,
    pub(super) ivc_witness: Witness,
}

/// Compute a fresh SNARK certificate for the epoch following `chain_state`.
/// Takes the data the aggregator already has and generates the next cert inline.
pub(super) fn build_new_cert(
    setup: &SharedSetup,
    keys: &KeysData,
    cert_srs: &ParamsKZG<Bls12>,
    chain_state: &State,
) -> NewCertData {
    let cert_pk = zk_lib::setup_pk(&setup.cert_relation, &keys.cert_vk);
    let (cert_fixed_bases, _) = fixed_bases_and_names(CERT_VK_NAME, keys.cert_vk.vk());

    // Derive next epoch and step from chain state
    let current_epoch = {
        let b = chain_state.current_epoch.to_bytes_le();
        u64::from_le_bytes(b[0..8].try_into().unwrap())
    };
    let new_epoch = current_epoch + 1;
    let step = {
        let b = chain_state.counter.to_bytes_le();
        u64::from_le_bytes(b[0..8].try_into().unwrap()) as usize
    };

    let merkle_root = chain_state.next_merkle_root;

    let (msg, preimage) = {
        let mut pm = ProtocolMessage::new();
        pm.set_message_part(ProtocolMessagePartKey::Digest, vec![(step as u8) + 2; 32]);
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
            new_epoch.to_le_bytes().into(),
        );
        let preimage = pm.get_preimage();
        let msg = pm.compute_hash();
        (jubjub_base_from_le_bytes(&msg), preimage)
    };

    let cert_instance = Certificate::format_instance(&(merkle_root, msg)).unwrap();
    let mut cert_witness = vec![];
    for j in 0..QUORUM as usize {
        let sig = setup.sks[j].sign(&[merkle_root, msg], &mut OsRng);
        let merkle_path = setup.merkle_tree.get_path(j);
        cert_witness.push((setup.leaves[j], merkle_path, sig, (j + 1) as u32));
    }

    let cert_proof = zk_lib::prove::<Certificate, PoseidonState<JubjubBase>>(
        cert_srs,
        &cert_pk,
        &setup.cert_relation,
        &(cert_instance[0], cert_instance[1]),
        cert_witness,
        OsRng,
    )
    .expect("cert proof generation failed");

    let cert_dual_msm = {
        let mut transcript =
            CircuitTranscript::<PoseidonState<JubjubBase>>::init_from_bytes(&cert_proof);
        let dm = prepare::<
            JubjubBase,
            KZGCommitmentScheme<Bls12>,
            CircuitTranscript<PoseidonState<JubjubBase>>,
        >(
            keys.cert_vk.vk(),
            &[&[C::identity()]],
            &[&[&cert_instance]],
            &mut transcript,
        )
        .expect("cert verify_prepare failed");
        transcript.assert_empty().expect("transcript not empty");
        dm
    };
    assert!(cert_dual_msm.clone().check(&cert_srs.verifier_params()));
    let mut cert_acc: Accumulator<BlstrsEmulation> = cert_dual_msm.into();
    cert_acc.extract_fixed_bases(&cert_fixed_bases);
    cert_acc.collapse();

    let ivc_witness = Witness::new(
        setup.genesis_sig.clone(),
        merkle_root,
        msg,
        preimage.try_into().unwrap(),
    );
    let ivc_next_state = State::new(
        JubjubBase::from((step + 1) as u64),
        msg,
        merkle_root,
        merkle_root,
        chain_state.next_protocol_params,
        chain_state.next_protocol_params,
        JubjubBase::from(new_epoch),
    );

    NewCertData {
        cert_proof,
        cert_acc,
        ivc_next_state,
        ivc_witness,
    }
}

/// Load an existing IVC chain state from disk.
/// Returns (state, ivc_proof_bytes, accumulator).
/// Skips the global field elements (5 × 32 bytes) which the caller re-derives.
pub(super) fn load_chain_state(path: &PathBuf) -> (State, Vec<u8>, Accumulator<BlstrsEmulation>) {
    let file =
        File::open(path).unwrap_or_else(|_| panic!("chain state not found at {}", path.display()));
    let mut r = BufReader::new(file);
    for _ in 0..5usize {
        read_fe(&mut r);
    }
    let state = read_state(&mut r);
    let proof = read_proof(&mut r);
    let acc = Accumulator::<BlstrsEmulation>::read(&mut r, SerdeFormat::RawBytesUnchecked)
        .expect("failed to read accumulator");
    (state, proof, acc)
}

/// Verify the previous IVC proof (Poseidon) to extract its accumulator,
/// then fold it together with the cert accumulator and previous accumulator.
/// Returns the collapsed next accumulator, asserted to pass the pairing check.
pub(super) fn compute_next_acc(
    ivc_srs: &ParamsKZG<Bls12>,
    srs: &ParamsKZG<Bls12>,
    keys: &KeysData,
    global: &Global,
    state: &State,
    acc: &Accumulator<BlstrsEmulation>,
    ivc_proof: &[u8],
    cert_acc: Accumulator<BlstrsEmulation>,
) -> Accumulator<BlstrsEmulation> {
    let public_inputs_prev = [
        global.as_public_input(),
        state.as_public_input(),
        AssignedAccumulator::as_public_input(acc),
    ]
    .concat();
    let proof_acc = verify_ivc_poseidon(
        ivc_srs,
        &keys.self_vk,
        &keys.self_fixed_bases,
        ivc_proof,
        &public_inputs_prev,
    );
    let mut next_acc = Accumulator::accumulate(&[acc.clone(), cert_acc, proof_acc]);
    next_acc.collapse();
    assert!(
        next_acc.check(&srs.s_g2().into(), &keys.combined_fixed_bases),
        "next_acc check failed"
    );
    next_acc
}

/// Construct the IVC circuit for step N+1 and its public inputs.
/// Consumes `new_cert`; call `new_cert.ivc_next_state.clone()` beforehand if
/// the caller needs it separately (e.g. to write to file).
pub(super) fn build_ivc_circuit(
    global: &Global,
    state: &State,
    new_cert: NewCertData,
    ivc_proof: Vec<u8>,
    acc: &Accumulator<BlstrsEmulation>,
    next_acc: &Accumulator<BlstrsEmulation>,
    keys: &KeysData,
) -> (IvcCircuit, Vec<JubjubBase>) {
    let circuit = IvcCircuit::new(
        global.clone(),
        state.clone(),
        new_cert.ivc_witness,
        new_cert.cert_proof,
        ivc_proof,
        acc.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );
    let public_inputs = [
        global.as_public_input(),
        new_cert.ivc_next_state.as_public_input(),
        AssignedAccumulator::as_public_input(next_acc),
    ]
    .concat();
    (circuit, public_inputs)
}

/// Generate an initial IVC chain of CHAIN_LENGTH certificates and save the chain state.
/// This represents an existing chain that the aggregator will later extend.
///
/// Saves: Global, State after step N, IVC proof bytes (Poseidon), accumulator.
///
/// Run with:
///   cargo test --release test_aggr::data_generators::generate_chain_state -- --include-ignored --nocapture
#[test]
#[ignore]
fn generate_chain_state() {
    let setup = build_shared_setup();
    let (cert_srs, ivc_srs) = open_srs_pair();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);
    let srs = open_params(K.max(K_INNER));

    let cert_pk = zk_lib::setup_pk(&setup.cert_relation, &keys.cert_vk);
    let self_pk = keygen_pk(
        keys.self_vk.clone(),
        &IvcCircuit::unknown(keys.cert_vk.vk()),
    )
    .unwrap();

    let (cert_fixed_bases, cert_fixed_base_names) =
        fixed_bases_and_names(CERT_VK_NAME, keys.cert_vk.vk());

    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    // Build cert witnesses and instances for steps 1..=CHAIN_LENGTH
    let mut cert_proofs: Vec<Vec<u8>> = vec![vec![]]; // index 0 = genesis (empty)
    let mut cert_accs = vec![trivial_acc(&cert_fixed_base_names)];

    let mut current_epoch = 5u64;
    let mut ivc_next_states = vec![State::new(
        JubjubBase::ONE,
        setup.genesis_msg,
        JubjubBase::ZERO,
        setup.genesis_next_merkle_root,
        JubjubBase::ZERO,
        setup.genesis_next_protocol_params,
        JubjubBase::from(current_epoch),
    )];
    let mut ivc_witnesses = vec![Witness::new(
        setup.genesis_sig.clone(),
        JubjubBase::ZERO,
        JubjubBase::ZERO,
        {
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
                current_epoch.to_le_bytes().into(),
            );
            pm.get_preimage().try_into().unwrap()
        },
    )];

    for step in 1..=CHAIN_LENGTH {
        current_epoch += 1;
        let (msg, preimage) = {
            let mut pm = ProtocolMessage::new();
            pm.set_message_part(ProtocolMessagePartKey::Digest, vec![(step as u8) + 2; 32]);
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
                current_epoch.to_le_bytes().into(),
            );
            let preimage = pm.get_preimage();
            let msg = pm.compute_hash();
            (jubjub_base_from_le_bytes(&msg), preimage)
        };

        ivc_next_states.push(State::new(
            JubjubBase::from((step + 1) as u64),
            msg,
            setup.genesis_next_merkle_root,
            setup.genesis_next_merkle_root,
            setup.genesis_next_protocol_params,
            setup.genesis_next_protocol_params,
            JubjubBase::from(current_epoch),
        ));
        ivc_witnesses.push(Witness::new(
            setup.genesis_sig.clone(),
            setup.genesis_next_merkle_root,
            msg,
            preimage.try_into().unwrap(),
        ));

        // Cert witness
        let cert_instance =
            Certificate::format_instance(&(setup.genesis_next_merkle_root, msg)).unwrap();
        let mut cert_witness = vec![];
        for j in 0..QUORUM as usize {
            let sig = setup.sks[j].sign(&[setup.genesis_next_merkle_root, msg], &mut OsRng);
            let merkle_path = setup.merkle_tree.get_path(j);
            cert_witness.push((setup.leaves[j], merkle_path, sig, (j + 1) as u32));
        }

        let cert_proof = zk_lib::prove::<Certificate, PoseidonState<JubjubBase>>(
            &cert_srs,
            &cert_pk,
            &setup.cert_relation,
            &(cert_instance[0], cert_instance[1]),
            cert_witness,
            OsRng,
        )
        .expect("cert proof generation failed");

        let cert_dual_msm = {
            let mut transcript =
                CircuitTranscript::<PoseidonState<JubjubBase>>::init_from_bytes(&cert_proof);
            let dm = prepare::<
                JubjubBase,
                KZGCommitmentScheme<Bls12>,
                CircuitTranscript<PoseidonState<JubjubBase>>,
            >(
                keys.cert_vk.vk(),
                &[&[C::identity()]],
                &[&[&cert_instance]],
                &mut transcript,
            )
            .expect("cert verify_prepare failed");
            transcript.assert_empty().expect("transcript not empty");
            dm
        };
        assert!(cert_dual_msm.clone().check(&cert_srs.verifier_params()));
        let mut cert_acc: Accumulator<BlstrsEmulation> = cert_dual_msm.into();
        cert_acc.extract_fixed_bases(&cert_fixed_bases);
        cert_acc.collapse();

        cert_proofs.push(cert_proof);
        cert_accs.push(cert_acc);
        println!("Cert step {} generated.", step);
    }

    // Prove IVC chain steps 0..=CHAIN_LENGTH (all Poseidon)
    let mut state = State::genesis();
    let mut self_proof: Vec<u8> = vec![];
    let mut acc = trivial_acc(&keys.combined_fixed_base_names);
    let mut next_acc = acc.clone();

    for i in 0..=CHAIN_LENGTH {
        let circuit = IvcCircuit::new(
            global.clone(),
            state.clone(),
            ivc_witnesses[i].clone(),
            cert_proofs[i].clone(),
            self_proof.clone(),
            acc.clone(),
            keys.cert_vk.vk(),
            &keys.self_vk,
        );
        let public_inputs = [
            global.as_public_input(),
            ivc_next_states[i].as_public_input(),
            AssignedAccumulator::as_public_input(&next_acc),
        ]
        .concat();

        let proof = prove_ivc_poseidon(&ivc_srs, &self_pk, &circuit, &public_inputs);
        let proof_acc = verify_ivc_poseidon(
            &ivc_srs,
            &keys.self_vk,
            &keys.self_fixed_bases,
            &proof,
            &public_inputs,
        );

        state = ivc_next_states[i].clone();
        acc = next_acc.clone();
        self_proof = proof.clone();

        if i < CHAIN_LENGTH {
            let mut accumulated =
                Accumulator::accumulate(&[next_acc.clone(), cert_accs[i + 1].clone(), proof_acc]);
            accumulated.collapse();
            assert!(
                accumulated.check(&srs.s_g2().into(), &keys.combined_fixed_bases),
                "IVC acc check failed at step {}",
                i
            );
            next_acc = accumulated;
        }

        println!("IVC step {} proved.", i);
    }

    // Save chain state
    let path = chain_state_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut w = BufWriter::new(File::create(&path).unwrap());

    // Global
    w.write_all(
        &global
            .as_public_input()
            .iter()
            .flat_map(|f| f.to_bytes_le())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    // State
    w.write_all(
        &state
            .as_public_input()
            .iter()
            .flat_map(|f| f.to_bytes_le())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    // IVC proof
    let proof_bytes = self_proof;
    w.write_all(&(proof_bytes.len() as u32).to_le_bytes())
        .unwrap();
    w.write_all(&proof_bytes).unwrap();
    // Accumulator
    acc.write(&mut w, SerdeFormat::RawBytesUnchecked).unwrap();

    println!("Chain state saved to {}", path.display());
}

/// Generate a fresh SNARK certificate for epoch CHAIN_LENGTH+1 and save cert data.
/// This certificate will be added to the chain by the aggregator test.
///
/// Saves: cert proof bytes, cert accumulator, cert public inputs, IVC witness, IVC next state.
///
/// Run with:
///   cargo test --release test_aggr::data_generators::generate_new_cert -- --include-ignored --nocapture
#[test]
#[ignore]
fn generate_new_cert() {
    let setup = build_shared_setup();
    let (cert_srs, _ivc_srs) = open_srs_pair();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &_ivc_srs);

    let cert_pk = zk_lib::setup_pk(&setup.cert_relation, &keys.cert_vk);
    let (cert_fixed_bases, _) = fixed_bases_and_names(CERT_VK_NAME, keys.cert_vk.vk());

    // Epoch for the new certificate = CHAIN_LENGTH + 1 steps after genesis epoch (5)
    let new_epoch = 5u64 + (CHAIN_LENGTH as u64) + 1;
    let step = CHAIN_LENGTH + 1;

    let (msg, preimage) = {
        let mut pm = ProtocolMessage::new();
        pm.set_message_part(ProtocolMessagePartKey::Digest, vec![(step as u8) + 2; 32]);
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
            new_epoch.to_le_bytes().into(),
        );
        let preimage = pm.get_preimage();
        let msg = pm.compute_hash();
        (jubjub_base_from_le_bytes(&msg), preimage)
    };

    let cert_instance =
        Certificate::format_instance(&(setup.genesis_next_merkle_root, msg)).unwrap();
    let mut cert_witness = vec![];
    for j in 0..QUORUM as usize {
        let sig = setup.sks[j].sign(&[setup.genesis_next_merkle_root, msg], &mut OsRng);
        let merkle_path = setup.merkle_tree.get_path(j);
        cert_witness.push((setup.leaves[j], merkle_path, sig, (j + 1) as u32));
    }

    let cert_proof = zk_lib::prove::<Certificate, PoseidonState<JubjubBase>>(
        &cert_srs,
        &cert_pk,
        &setup.cert_relation,
        &(cert_instance[0], cert_instance[1]),
        cert_witness,
        OsRng,
    )
    .expect("cert proof generation failed");

    let cert_dual_msm = {
        let mut transcript =
            CircuitTranscript::<PoseidonState<JubjubBase>>::init_from_bytes(&cert_proof);
        let dm = prepare::<
            JubjubBase,
            KZGCommitmentScheme<Bls12>,
            CircuitTranscript<PoseidonState<JubjubBase>>,
        >(
            keys.cert_vk.vk(),
            &[&[C::identity()]],
            &[&[&cert_instance]],
            &mut transcript,
        )
        .expect("cert verify_prepare failed");
        transcript.assert_empty().expect("transcript not empty");
        dm
    };
    assert!(cert_dual_msm.clone().check(&cert_srs.verifier_params()));
    let mut cert_acc: Accumulator<BlstrsEmulation> = cert_dual_msm.into();
    cert_acc.extract_fixed_bases(&cert_fixed_bases);
    cert_acc.collapse();

    // IVC witness and next state for step N+1
    let ivc_witness = Witness::new(
        setup.genesis_sig.clone(),
        setup.genesis_next_merkle_root,
        msg,
        preimage.try_into().unwrap(),
    );
    let ivc_next_state = State::new(
        JubjubBase::from((step + 1) as u64),
        msg,
        setup.genesis_next_merkle_root,
        setup.genesis_next_merkle_root,
        setup.genesis_next_protocol_params,
        setup.genesis_next_protocol_params,
        JubjubBase::from(new_epoch),
    );

    // Save new cert data
    let path = new_cert_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut w = BufWriter::new(File::create(&path).unwrap());

    // Cert proof
    w.write_all(&(cert_proof.len() as u32).to_le_bytes())
        .unwrap();
    w.write_all(&cert_proof).unwrap();
    // Cert accumulator
    cert_acc
        .write(&mut w, SerdeFormat::RawBytesUnchecked)
        .unwrap();
    // Cert public inputs (2 field elements)
    for f in &cert_instance {
        w.write_all(&f.to_bytes_le()).unwrap();
    }
    // IVC next state
    for f in &ivc_next_state.as_public_input() {
        w.write_all(&f.to_bytes_le()).unwrap();
    }
    // IVC witness fields
    for f in &[ivc_witness.cert_merkle_root, ivc_witness.cert_msg] {
        w.write_all(&f.to_bytes_le()).unwrap();
    }
    w.write_all(&ivc_witness.msg_preimage).unwrap();

    println!("New cert saved to {}", path.display());
}

/// Generate and save the deterministic protocol data the verifier is supposed to know.
///
/// Saves: global (5 field elements), self_vk, combined_fixed_bases.
/// This data is fixed for a given circuit and genesis — computed once and distributed.
///
/// Run with:
///   cargo test --release test_timings::data_generators::generate_protocol_data -- --include-ignored --nocapture
#[test]
#[ignore]
fn generate_protocol_data() {
    let setup = build_shared_setup();
    let (cert_srs, ivc_srs) = open_srs_pair();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);

    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    let path = protocol_data_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut w = BufWriter::new(File::create(&path).unwrap());

    // global (5 field elements)
    for f in &global.as_public_input() {
        w.write_all(&f.to_bytes_le()).unwrap();
    }

    // self_vk
    keys.self_vk
        .write(&mut w, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    // combined_fixed_bases: count + (name_len + name_bytes + G1_point) per entry
    w.write_all(&(keys.combined_fixed_bases.len() as u32).to_le_bytes())
        .unwrap();
    for (name, point) in &keys.combined_fixed_bases {
        let name_bytes = name.as_bytes();
        w.write_all(&(name_bytes.len() as u32).to_le_bytes())
            .unwrap();
        w.write_all(name_bytes).unwrap();
        point.write(&mut w, SerdeFormat::RawBytesUnchecked).unwrap();
    }

    println!("Protocol data saved to {}", path.display());
    println!("  global:               5 field elements");
    println!("  self_vk:              serialized");
    println!(
        "  combined_fixed_bases: {} entries",
        keys.combined_fixed_bases.len()
    );
}

/// Generate and save the result that the aggregator sends to the verifier.
///
/// Loads chain_state.bin, generates a new certificate inline, computes the next
/// accumulator, proves the IVC step with Blake2b, and saves:
///   final_proof (u32 len + bytes) | next_acc | ivc_next_state (7 × 32 bytes)
///
/// Prerequisites:
///   cargo test --release test_timings::data_generators::generate_chain_state -- --include-ignored --nocapture
///
/// Run with:
///   cargo test --release test_timings::data_generators::generate_aggr_result -- --include-ignored --nocapture
#[test]
#[ignore]
fn generate_aggr_result() {
    // Setup
    println!("Setting up keys...");
    let setup = build_shared_setup();
    let (cert_srs, ivc_srs) = open_srs_pair();
    let keys = setup_keys(&setup.cert_relation, &cert_srs, &ivc_srs);
    let srs = open_params(K.max(K_INNER));
    let self_pk = keygen_pk(
        keys.self_vk.clone(),
        &IvcCircuit::unknown(keys.cert_vk.vk()),
    )
    .unwrap();
    let global = Global::new(
        setup.genesis_msg,
        setup.genesis_vk.clone(),
        keys.cert_vk.vk(),
        &keys.self_vk,
    );

    // Step 1: Load chain state
    let (state, ivc_proof, acc) = load_chain_state(&chain_state_path());
    println!("Chain state loaded. IVC proof: {} bytes", ivc_proof.len());

    // Step 2: Build new certificate
    let new_cert = build_new_cert(&setup, &keys, &cert_srs, &state);
    println!(
        "New cert generated. Proof: {} bytes",
        new_cert.cert_proof.len()
    );

    // Step 3: Compute next accumulator
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

    // Step 4: Build IVC circuit
    // Clone ivc_next_state before new_cert is consumed by build_ivc_circuit.
    let ivc_next_state = new_cert.ivc_next_state.clone();
    let (circuit, public_inputs) =
        build_ivc_circuit(&global, &state, new_cert, ivc_proof, &acc, &next_acc, &keys);

    // Step 5: Prove with Blake2b
    println!("Proving IVC step N+1 with Blake2b...");
    let t = std::time::Instant::now();
    let final_proof = prove_ivc_blake2(&ivc_srs, &self_pk, &circuit, &public_inputs);
    println!(
        "Proved in {:.1}s ({} bytes)",
        t.elapsed().as_secs_f64(),
        final_proof.len()
    );

    // Save
    let path = aggr_result_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut w = BufWriter::new(File::create(&path).unwrap());
    w.write_all(&(final_proof.len() as u32).to_le_bytes())
        .unwrap();
    w.write_all(&final_proof).unwrap();
    next_acc
        .write(&mut w, SerdeFormat::RawBytesUnchecked)
        .unwrap();
    for f in &ivc_next_state.as_public_input() {
        w.write_all(&f.to_bytes_le()).unwrap();
    }

    println!("Aggregator result saved to {}", path.display());
}
