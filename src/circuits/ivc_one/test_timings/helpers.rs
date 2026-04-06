use group::Group;
use midnight_proofs::{
    plonk::{ProvingKey, VerifyingKey},
    utils::{SerdeFormat, helpers::ProcessedSerdeObject},
};
use midnight_zk_stdlib::{self as zk_lib, MidnightVK};
use rand_core::OsRng;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read as IoRead},
};

use crate::{
    Accumulator, Bls12, BlstrsEmulation, CERT_VK_NAME, CircuitTranscript, IVC_ONE_NAME, JubjubBase,
    KZGCommitmentScheme, ParamsKZG, PoseidonState, Transcript,
    certificate::Certificate,
    create_proof,
    ivc_one::{
        circuit::IvcCircuit,
        state::{State, fixed_bases_and_names},
    },
    keygen_vk_with_k, prepare,
    utils::jubjub_base_from_le_bytes,
};

use super::{C, K, K_INNER};

/// Read a single field element written as 32 bytes in little-endian canonical form.
pub(super) fn read_fe<R: IoRead>(r: &mut R) -> JubjubBase {
    let mut buf = [0u8; 32];
    r.read_exact(&mut buf).unwrap();
    jubjub_base_from_le_bytes(&buf)
}

/// Read an IVC `State` from 7 consecutive field elements in little-endian canonical form.
/// Order: counter, msg, merkle_root, next_merkle_root, protocol_params, next_protocol_params, current_epoch.
pub(super) fn read_state<R: IoRead>(r: &mut R) -> State {
    State::new(
        read_fe(r), // counter
        read_fe(r), // msg
        read_fe(r), // merkle_root
        read_fe(r), // next_merkle_root
        read_fe(r), // protocol_params
        read_fe(r), // next_protocol_params
        read_fe(r), // current_epoch
    )
}

/// Read a length-prefixed proof blob. Format: u32 LE byte count followed by that many bytes.
pub(super) fn read_proof<R: IoRead>(r: &mut R) -> Vec<u8> {
    let mut buf4 = [0u8; 4];
    r.read_exact(&mut buf4).unwrap();
    let len = u32::from_le_bytes(buf4) as usize;
    let mut proof = vec![0u8; len];
    r.read_exact(&mut proof).unwrap();
    proof
}

/// Keys and parameters derived from the KZG SRS and circuit structure.
/// Computed once by `setup_keys` and shared across all tests to avoid redundant work.
pub(super) struct KeysData {
    pub(super) cert_vk: MidnightVK,
    pub(super) self_vk: VerifyingKey<JubjubBase, KZGCommitmentScheme<Bls12>>,
    pub(super) combined_fixed_bases: BTreeMap<String, C>,
    pub(super) combined_fixed_base_names: Vec<String>,
    pub(super) self_fixed_bases: BTreeMap<String, C>,
}

/// Load KZG parameters from file. Panics if the file is not found or cannot be read.
pub(super) fn open_params(k: u32) -> ParamsKZG<Bls12> {
    let path = format!("examples/assets/params_kzg_unsafe_{}", k);
    let file = File::open(&path).unwrap_or_else(|_| panic!("KZG params not found at {}", path));
    let mut reader = BufReader::new(file);
    ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
}

/// Load KZG parameters for both the certificate and IVC circuits, downsizing if needed.
pub(super) fn open_srs_pair() -> (ParamsKZG<Bls12>, ParamsKZG<Bls12>) {
    let k_max = K.max(K_INNER);
    let cert_srs = {
        let mut s = open_params(k_max);
        if K_INNER < k_max {
            s.downsize(K_INNER);
        }
        s
    };
    let ivc_srs = {
        let mut s = open_params(k_max);
        if K < k_max {
            s.downsize(K);
        }
        s
    };
    (cert_srs, ivc_srs)
}

/// Set up the proving and verifying keys for both the certificate and IVC circuits, and prepare the combined fixed bases.
pub(super) fn setup_keys(
    cert_relation: &Certificate,
    cert_srs: &ParamsKZG<Bls12>,
    ivc_srs: &ParamsKZG<Bls12>,
) -> KeysData {
    let cert_vk = zk_lib::setup_vk(cert_srs, cert_relation);
    let (cert_fixed_bases, _) = fixed_bases_and_names(CERT_VK_NAME, cert_vk.vk());

    let default_ivc_circuit = IvcCircuit::unknown(cert_vk.vk());
    let self_vk =
        keygen_vk_with_k::<_, KZGCommitmentScheme<Bls12>, _>(ivc_srs, &default_ivc_circuit, K)
            .unwrap();
    let (self_fixed_bases, _) = fixed_bases_and_names(IVC_ONE_NAME, &self_vk);

    let mut combined_fixed_bases = BTreeMap::new();
    combined_fixed_bases.extend(cert_fixed_bases);
    combined_fixed_bases.extend(self_fixed_bases.clone());
    let combined_fixed_base_names: Vec<_> = combined_fixed_bases.keys().cloned().collect();

    KeysData {
        cert_vk,
        self_vk,
        combined_fixed_bases,
        combined_fixed_base_names,
        self_fixed_bases,
    }
}

/// IVC prove with Poseidon transcript
pub(super) fn prove_ivc_poseidon(
    ivc_srs: &ParamsKZG<Bls12>,
    self_pk: &ProvingKey<JubjubBase, KZGCommitmentScheme<Bls12>>,
    circuit: &IvcCircuit,
    public_inputs: &[JubjubBase],
) -> Vec<u8> {
    let mut transcript = CircuitTranscript::<PoseidonState<JubjubBase>>::init();
    create_proof::<
        JubjubBase,
        KZGCommitmentScheme<Bls12>,
        CircuitTranscript<PoseidonState<JubjubBase>>,
        IvcCircuit,
    >(
        ivc_srs,
        self_pk,
        &[circuit.clone()],
        1,
        &[&[&[], public_inputs]],
        OsRng,
        &mut transcript,
    )
    .expect("IVC proof generation (Poseidon) failed");
    transcript.finalize()
}

/// IVC prove with Blake2b transcript
pub(super) fn prove_ivc_blake2(
    ivc_srs: &ParamsKZG<Bls12>,
    self_pk: &ProvingKey<JubjubBase, KZGCommitmentScheme<Bls12>>,
    circuit: &IvcCircuit,
    public_inputs: &[JubjubBase],
) -> Vec<u8> {
    let mut transcript = CircuitTranscript::<blake2b_simd::State>::init();
    create_proof::<
        JubjubBase,
        KZGCommitmentScheme<Bls12>,
        CircuitTranscript<blake2b_simd::State>,
        IvcCircuit,
    >(
        ivc_srs,
        self_pk,
        &[circuit.clone()],
        1,
        &[&[&[], public_inputs]],
        OsRng,
        &mut transcript,
    )
    .expect("IVC proof generation (Blake2b) failed");
    transcript.finalize()
}

/// Verify an IVC proof using the Poseidon transcript and extract the accumulator from the proof.
pub(super) fn verify_ivc_poseidon(
    ivc_srs: &ParamsKZG<Bls12>,
    self_vk: &VerifyingKey<JubjubBase, KZGCommitmentScheme<Bls12>>,
    self_fixed_bases: &BTreeMap<String, C>,
    proof: &[u8],
    public_inputs: &[JubjubBase],
) -> Accumulator<BlstrsEmulation> {
    let mut transcript = CircuitTranscript::<PoseidonState<JubjubBase>>::init_from_bytes(proof);
    let dual_msm = prepare::<
        JubjubBase,
        KZGCommitmentScheme<Bls12>,
        CircuitTranscript<PoseidonState<JubjubBase>>,
    >(
        self_vk,
        &[&[C::identity()]],
        &[&[public_inputs]],
        &mut transcript,
    )
    .expect("IVC verify_prepare (Poseidon) failed");
    transcript.assert_empty().expect("transcript not empty");
    assert!(dual_msm.clone().check(&ivc_srs.verifier_params()));
    let mut acc: Accumulator<BlstrsEmulation> = dual_msm.into();
    acc.extract_fixed_bases(self_fixed_bases);
    acc.collapse();
    acc
}

/// Verify an IVC proof using the Blake2b transcript and extract the accumulator from the proof.
pub(super) fn verify_ivc_blake2(
    ivc_srs: &ParamsKZG<Bls12>,
    self_vk: &VerifyingKey<JubjubBase, KZGCommitmentScheme<Bls12>>,
    self_fixed_bases: &BTreeMap<String, C>,
    proof: &[u8],
    public_inputs: &[JubjubBase],
) -> Accumulator<BlstrsEmulation> {
    let mut transcript = CircuitTranscript::<blake2b_simd::State>::init_from_bytes(proof);
    let dual_msm =
        prepare::<JubjubBase, KZGCommitmentScheme<Bls12>, CircuitTranscript<blake2b_simd::State>>(
            self_vk,
            &[&[C::identity()]],
            &[&[public_inputs]],
            &mut transcript,
        )
        .expect("IVC verify_prepare (Blake2b) failed");
    transcript.assert_empty().expect("transcript not empty");
    assert!(dual_msm.clone().check(&ivc_srs.verifier_params()));
    let mut acc: Accumulator<BlstrsEmulation> = dual_msm.into();
    acc.extract_fixed_bases(self_fixed_bases);
    acc.collapse();
    acc
}

/// Read a `combined_fixed_bases` map written by `generate_protocol_data`.
/// Format: count (u32 LE) + per entry: name_len (u32 LE) + name bytes + C point.
pub(super) fn read_combined_fixed_bases<R: IoRead>(r: &mut R) -> BTreeMap<String, C> {
    let mut buf4 = [0u8; 4];
    r.read_exact(&mut buf4).unwrap();
    let count = u32::from_le_bytes(buf4) as usize;
    let mut map = BTreeMap::new();
    for _ in 0..count {
        r.read_exact(&mut buf4).unwrap();
        let name_len = u32::from_le_bytes(buf4) as usize;
        let mut name_bytes = vec![0u8; name_len];
        r.read_exact(&mut name_bytes).unwrap();
        let name = String::from_utf8(name_bytes).unwrap();
        let point = <C as ProcessedSerdeObject>::read(r, SerdeFormat::RawBytesUnchecked).unwrap();
        map.insert(name, point);
    }
    map
}
