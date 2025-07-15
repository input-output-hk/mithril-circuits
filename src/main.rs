//! Examples on how to perform ECC operations using the ECC Chip inside of
//! ZkStdLib.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::rc::Rc;
use std::time::Instant;

use ff::{Field, PrimeField};
use group::Group;
use rand::rngs::OsRng;

use blstrs::{
    Bls12, Fq as JubjubBase, Fr as JubjubScalar, Fr, G1Projective as BlstG1, JubjubAffine,
    JubjubExtended as Jubjub, JubjubExtended, JubjubSubgroup, MODULUS,
};
use halo2curves::CurveAffine;
use midnight_circuits::ecc::curves::CircuitCurve;
use midnight_circuits::hash::poseidon::PoseidonState;
use midnight_circuits::types::Instantiable;
use midnight_circuits::verifier::{Accumulator, AssignedAccumulator, AssignedVk, Msm};
use midnight_circuits::{
    compact_std_lib::{self, MidnightCircuit, Relation},
    ecc::{hash_to_curve::HashToCurveGadget, native::EccChip, native::ScalarVar},
    field::AssignedNative,
    hash::poseidon::PoseidonChip,
    instructions::{
        AssertionInstructions, AssignmentInstructions, ConversionInstructions, EccInstructions,
        HashToCurveCPU, PublicInputInstructions, hash::HashCPU,
    },
    testing_utils::plonk_api::filecoin_srs,
    types::AssignedNativePoint,
    verifier,
};
use midnight_proofs::dev::MockProver;
use midnight_proofs::plonk::{
    ConstraintSystem, create_proof, keygen_pk, keygen_vk_with_k, prepare,
};
use midnight_proofs::poly::EvaluationDomain;
use midnight_proofs::poly::kzg::KZGCommitmentScheme;
use midnight_proofs::poly::kzg::params::ParamsKZG;
use midnight_proofs::transcript::{CircuitTranscript, Transcript};
use midnight_proofs::utils::SerdeFormat;
use midnight_proofs::{
    circuit::{Layouter, Value},
    dev::CircuitCost,
    plonk::Error,
};
use mithril_circuits::circuits::certificate::Certificate;
use mithril_circuits::ivc::{IvcCircuit, configure_ivc_circuit};
use mithril_circuits::{Signature, SigningKey, VerificationKey, ivc_with_inner};

//type F = JubjubBase;
type C = blstrs::G1Projective;
type CAffine = blstrs::G1Affine;
type E = blstrs::Bls12;
type CBase = <C as CircuitCurve>::Base;
type F = <CAffine as CurveAffine>::ScalarExt;

// create unsafe params for tests
fn create(k: u32) {
    let path = format!("examples/assets/params_kzg_unsafe_{}", k);
    // Step 1: Create an instance of ParamsKZG
    let params: ParamsKZG<Bls12> = ParamsKZG::unsafe_setup(k, OsRng);

    // Step 2: Open a file for writing
    let file = File::create(&path).unwrap();
    let mut writer = BufWriter::new(file);

    // Step 3: Write the ParamsKZG to the file
    params
        .write_custom(&mut writer, SerdeFormat::RawBytesUnchecked)
        .unwrap();

    println!("ParamsKZG written to {}", path);
}

fn open(k: u32) -> ParamsKZG<Bls12> {
    let path = format!("examples/assets/params_kzg_unsafe_{}", k);
    let file = File::open(path).unwrap();
    let mut reader = BufReader::new(file);
    let params: ParamsKZG<Bls12> =
        ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap();

    params
}

fn test_certificate() {
    const K: u32 = 11;
    let srs = filecoin_srs(K);

    let relation = Certificate;

    {
        // print circuit size
        let circuit = MidnightCircuit::from_relation(&relation);
        let cost = CircuitCost::<BlstG1, _>::measure(11, &circuit);
        println!("Circuit cost: {:?}", cost);
    }

    let start = Instant::now();
    let vk = compact_std_lib::setup_vk(&srs, &relation);
    let pk = compact_std_lib::setup_pk(&relation, &vk);
    let duration = start.elapsed(); // Measure the elapsed time after proof generation.
    println!("\nvk pk generation took: {:?}", duration);

    {
        // let base_one = JubjubBase::ONE;
        // let hash = JubjubHashToCurve::hash_to_curve(&[base_one]);

        // subgroup order: 0xe7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
        // let r = MODULUS;
        // let hr = hash * r;
        // println!("\n hr: {:?}", hr);
        // println!("hr is identity: {:?}", hr.is_identity());
    }

    // message to be signed
    let msg = F::from(42);
    println!("\n msg: {:?}", msg);

    let usk = SigningKey::generate(&mut OsRng);
    let uvk = VerificationKey::from(&usk);
    let sig = usk.sign(msg, &mut OsRng);
    sig.verify(msg, &uvk).unwrap();

    let instance = msg;
    let witness = (uvk, sig);

    let start = Instant::now();
    let proof = compact_std_lib::prove::<Certificate, blake2b_simd::State>(
        &srs, &pk, &relation, &instance, witness, OsRng,
    )
    .expect("Proof generation should not fail");
    let duration = start.elapsed(); // Measure the elapsed time after proof generation.
    println!("\nProof generation took: {:?}", duration);

    println!("\nproof size: {:?}", proof.len());

    let start = Instant::now();
    assert!(
        compact_std_lib::verify::<Certificate, blake2b_simd::State>(
            &srs.verifier_params(),
            &vk,
            &instance,
            &proof
        )
        .is_ok()
    );
    let duration = start.elapsed(); // Measure the elapsed time after proof generation.
    println!("\nProof verification took: {:?}", duration);
}

fn test_ivc() {
    let self_k = 19;

    let mut self_cs = ConstraintSystem::default();
    configure_ivc_circuit(&mut self_cs);
    let self_domain = EvaluationDomain::new(self_cs.degree() as u32, self_k);

    let default_ivc_circuit = IvcCircuit {
        self_vk: (self_domain.clone(), self_cs.clone(), Value::unknown()),
        prev_state: Value::unknown(),
        prev_proof: Value::unknown(),
        prev_acc: Value::unknown(),
    };

    //let srs = filecoin_srs(self_k);
    //
    // let t = Instant::now();
    // let srs: ParamsKZG<E> = ParamsKZG::unsafe_setup(self_k, OsRng);
    // println!("(Unsafe) SRS generation in {} s", t.elapsed().as_secs());

    let srs = open(self_k);

    let cost = CircuitCost::<C, _>::measure(self_k, &default_ivc_circuit);
    println!("Circuit cost: {:?}", cost);

    let start = Instant::now();
    let vk = keygen_vk_with_k(&srs, &default_ivc_circuit, self_k).unwrap();
    let pk = keygen_pk(vk.clone(), &default_ivc_circuit).unwrap();
    println!("Computed vk and pk in {:?} s", start.elapsed());

    let mut fixed_bases = BTreeMap::new();
    fixed_bases.insert(String::from("com_instance"), C::identity());
    fixed_bases.extend(midnight_circuits::verifier::fixed_bases("self_vk", &vk));
    let fixed_base_names = fixed_bases.keys().cloned().collect::<Vec<_>>();

    // This trivial accumulator must have a single base and scalar of F::ONE, and
    // the base has to be the default point of C. This is because when parsing
    // an empty proof, our transcript gadget places a default point on every
    // `read_point`. Note that the `base` is left untouched on during the
    // handling of genesis, because `scale_by_bit` only modifies the scalars.
    //
    // On the other hand, the scalar has to be F::ONE because it is the value
    // obtained after a `collapse` (the last step before constraining the acc as
    // a public input).
    let trivial_acc = Accumulator::<C>::new(
        Msm::new(&[C::default()], &[F::ONE], &BTreeMap::new()),
        Msm::new(
            &[C::default()],
            &[F::ONE],
            &fixed_base_names
                .iter()
                .map(|name| (name.clone(), F::ZERO))
                .collect(),
        ),
    );

    // Set the previous values for state (to genesis), proof and acc.
    let mut prev_state = F::ZERO;
    let mut prev_proof = vec![];
    let mut prev_acc = trivial_acc.clone();

    // Set the state (and acc) that we will prove (they are PI to the proof).
    let mut state = prev_state + F::ONE;
    let mut acc = trivial_acc;

    // Run the IVC loop.
    for i in 0..1 {
        let circuit = IvcCircuit {
            self_vk: (
                self_domain.clone(),
                self_cs.clone(),
                Value::known(vk.transcript_repr()),
            ),
            prev_state: Value::known(prev_state),
            prev_proof: Value::known(prev_proof.clone()),
            prev_acc: Value::known(prev_acc.clone()),
        };

        let mut public_inputs = AssignedVk::<C>::as_public_input(&vk);
        public_inputs.extend(AssignedNative::<F>::as_public_input(&state));
        public_inputs.extend(AssignedAccumulator::as_public_input(&acc));

        let start = Instant::now();
        let proof = {
            let mut transcript = CircuitTranscript::<PoseidonState<F>>::init();
            create_proof::<
                F,
                KZGCommitmentScheme<E>,
                CircuitTranscript<PoseidonState<F>>,
                IvcCircuit,
            >(
                &srs,
                &pk,
                &[circuit.clone()],
                1,
                &[&[&[], &public_inputs]],
                OsRng,
                &mut transcript,
            )
            .unwrap_or_else(|_| panic!("Problem creating the {i}-th IVC proof"));
            transcript.finalize()
        };
        println!("{i}-th IVC proof created in {:?}", start.elapsed());
        println!("proof size {:?}", proof.len());

        let proof_acc: Accumulator<C> = {
            let mut transcript = CircuitTranscript::<PoseidonState<F>>::init_from_bytes(&proof);
            let dual_msm =
                prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
                    &vk,
                    &[&[C::identity()]],
                    &[&[&public_inputs]],
                    &mut transcript,
                )
                .expect("Verification failed");

            assert!(dual_msm.clone().check(&srs.verifier_params()));

            let mut proof_acc: Accumulator<C> = dual_msm.into();
            proof_acc.extract_fixed_bases(&fixed_bases);
            proof_acc.collapse();
            proof_acc
        };

        // Prepare the witnesses of the next iteration.
        prev_state = state;
        prev_proof = proof;
        prev_acc = acc.clone();

        // If `acc` satisfies the invariant and `proof` is valid, we know that `state`
        // must be valid. We can asset the validity of both at the same time by
        // accumulating them first.
        let mut accumulated = proof_acc.accumulate(&acc);
        accumulated.collapse();

        assert!(
            accumulated.check(&srs.s_g2().into(), &fixed_bases),
            "IVC acc verification failed"
        );

        println!("Asserted validity of state {:?}", state);

        // Set the new goals (public inputs) for the next iteration.
        state += F::ONE;
        acc = accumulated;
    }
}

fn test_ivc_with_inner() {
    use ivc_with_inner::{IvcCircuit, configure_ivc_circuit};

    const K: u32 = 20;

    // create unsafe parameters once
    // create(K);
    let srs = open(K);

    // set up inner circuit
    println!("setting up inner circuit...");
    const K_INNER: u32 = 11;
    let mut inner_srs = srs.clone();
    inner_srs.downsize(K_INNER);

    let relation = Certificate;
    // let inner_circuit = MidnightCircuit::from_relation(&relation);
    let start = Instant::now();
    let inner_vk = compact_std_lib::setup_vk(&inner_srs, &relation);
    let inner_pk = compact_std_lib::setup_pk(&relation, &inner_vk);
    let duration = start.elapsed(); // Measure the elapsed time after proof generation.
    println!("inner circuit vk pk generation took: {:?}", duration);

    // message to be signed
    let msg = F::from(42);
    let usk = SigningKey::generate(&mut OsRng);
    let uvk = VerificationKey::from(&usk);
    let sig = usk.sign(msg, &mut OsRng);
    sig.verify(msg, &uvk).unwrap();

    let inner_instance = msg;
    let inner_witness = (uvk, sig);

    let start = Instant::now();
    let inner_proof = compact_std_lib::prove::<Certificate, PoseidonState<F>>(
        &inner_srs,
        &inner_pk,
        &relation,
        &inner_instance,
        inner_witness,
        OsRng,
    )
    .expect("Proof generation should not fail");
    let duration = start.elapsed(); // Measure the elapsed time after proof generation.
    println!("Inner circuit proof generation took: {:?}", duration);

    let inner_dual_msm = {
        let mut transcript = CircuitTranscript::<PoseidonState<F>>::init_from_bytes(&inner_proof);
        prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
            inner_vk.vk(),
            &[&[C::identity()]],
            &[&[&[inner_instance]]],
            &mut transcript,
        )
        .expect("Problem preparing the inner proof")
    };
    assert!(inner_dual_msm.clone().check(&inner_srs.verifier_params()));

    let mut inner_fixed_bases = BTreeMap::new();
    inner_fixed_bases.insert(String::from("com_instance"), C::identity());
    inner_fixed_bases.extend(verifier::fixed_bases("inner_vk", &inner_vk.vk()));

    let mut inner_acc: Accumulator<C> = inner_dual_msm.into();
    inner_acc.extract_fixed_bases(&inner_fixed_bases);
    assert!(inner_acc.check(&inner_srs.s_g2().into(), &inner_fixed_bases));
    inner_acc.collapse();

    // ivc circuit with inner vk
    let mut self_cs = ConstraintSystem::default();
    configure_ivc_circuit(&mut self_cs);
    let self_domain = EvaluationDomain::new(self_cs.degree() as u32, K);

    let default_ivc_circuit = IvcCircuit {
        self_vk: (self_domain.clone(), self_cs.clone(), Value::unknown()),
        prev_state: Value::unknown(),
        prev_proof: Value::unknown(),
        prev_acc: Value::unknown(),
        inner_vk: (
            inner_vk.vk().get_domain().clone(),
            inner_vk.vk().cs().clone(),
            Value::known(inner_vk.vk().transcript_repr()),
        ),
        inner_instances: Value::known([inner_instance]),
        inner_proof: Value::known(inner_proof.clone()),
    };

    let cost = CircuitCost::<C, _>::measure(K, &default_ivc_circuit);
    println!("IVC Circuit cost: {:?}", cost);

    let start = Instant::now();
    let vk = keygen_vk_with_k(&srs, &default_ivc_circuit, K).unwrap();
    let pk = keygen_pk(vk.clone(), &default_ivc_circuit).unwrap();
    println!("Computed IVC circuit vk and pk in {:?} s", start.elapsed());

    let mut self_fixed_bases = BTreeMap::new();
    self_fixed_bases.insert(String::from("com_instance"), C::identity());
    self_fixed_bases.extend(verifier::fixed_bases("self_vk", &vk));
    let self_fixed_base_names = self_fixed_bases.keys().cloned().collect::<Vec<_>>();

    let mut fixed_bases = BTreeMap::new();
    fixed_bases.extend(inner_fixed_bases.clone());
    fixed_bases.extend(self_fixed_bases.clone());
    let fixed_base_names = fixed_bases.keys().cloned().collect::<Vec<_>>();

    let trivial_acc = Accumulator::<C>::new(
        Msm::new(&[C::default()], &[F::ONE], &BTreeMap::new()),
        Msm::new(
            &[C::default()],
            &[F::ONE],
            &fixed_base_names
                .iter()
                .map(|name| (name.clone(), F::ZERO))
                .collect(),
        ),
    );

    let self_trivial_acc = Accumulator::<C>::new(
        Msm::new(&[C::default()], &[F::ONE], &BTreeMap::new()),
        Msm::new(
            &[C::default()],
            &[F::ONE],
            &self_fixed_base_names
                .iter()
                .map(|name| (name.clone(), F::ZERO))
                .collect(),
        ),
    );

    // Set the previous values for state (to genesis), proof and acc.
    let mut prev_state = F::ZERO;
    let mut prev_proof = vec![];
    let mut prev_acc = trivial_acc.clone();

    // Set the state (and acc) that we will prove (they are PI to the proof).
    let mut state = prev_state + F::ONE;
    let mut inner_with_trivial_acc = inner_acc.accumulate(&trivial_acc);
    inner_with_trivial_acc.collapse();
    //

    assert!(
        inner_with_trivial_acc.check(&srs.s_g2().into(), &fixed_bases),
        "IVC acc verification failed"
    );

    let mut acc = self_trivial_acc.accumulate(&inner_with_trivial_acc);
    acc.collapse();

    for i in 0..3 {
        let circuit = IvcCircuit {
            self_vk: (
                self_domain.clone(),
                self_cs.clone(),
                Value::known(vk.transcript_repr()),
            ),
            prev_state: Value::known(prev_state),
            prev_proof: Value::known(prev_proof.clone()),
            prev_acc: Value::known(prev_acc.clone()),
            inner_vk: (
                inner_vk.vk().get_domain().clone(),
                inner_vk.vk().cs().clone(),
                Value::known(inner_vk.vk().transcript_repr()),
            ),
            inner_instances: Value::known([inner_instance]),
            inner_proof: Value::known(inner_proof.clone()),
        };

        let mut public_inputs = AssignedVk::<C>::as_public_input(&inner_vk.vk());
        public_inputs.extend(AssignedVk::<C>::as_public_input(&vk));
        public_inputs.extend(AssignedNative::<F>::as_public_input(&state));
        public_inputs.extend(AssignedAccumulator::as_public_input(&acc));

        // let prover = MockProver::run(K, &circuit, vec![vec![], public_inputs.clone()]).unwrap();
        // assert_eq!(prover.verify(), Ok(()));

        let start = Instant::now();
        let proof = {
            let mut transcript = CircuitTranscript::<PoseidonState<F>>::init();
            create_proof::<
                F,
                KZGCommitmentScheme<E>,
                CircuitTranscript<PoseidonState<F>>,
                IvcCircuit,
            >(
                &srs,
                &pk,
                &[circuit.clone()],
                1,
                &[&[&[], &public_inputs]],
                OsRng,
                &mut transcript,
            )
            .unwrap_or_else(|_| panic!("Problem creating the IVC proof"));
            transcript.finalize()
        };

        println!("{i}-th IVC proof created in {:?}", start.elapsed());
        println!("proof size {:?}", proof.len());

        let proof_acc: Accumulator<C> = {
            let mut transcript = CircuitTranscript::<PoseidonState<F>>::init_from_bytes(&proof);
            let dual_msm =
                prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
                    &vk,
                    &[&[C::identity()]],
                    &[&[&public_inputs]],
                    &mut transcript,
                )
                .expect("Verification failed");

            assert!(dual_msm.clone().check(&srs.verifier_params()));

            let mut proof_acc: Accumulator<C> = dual_msm.into();
            proof_acc.extract_fixed_bases(&self_fixed_bases);
            proof_acc.collapse();
            proof_acc
        };

        // Prepare the witnesses of the next iteration.
        prev_state = state;
        prev_proof = proof;
        prev_acc = acc.clone();

        // If `acc` satisfies the invariant and `proof` is valid, we know that `state`
        // must be valid. We can asset the validity of both at the same time by
        // accumulating them first.
        let mut inner_with_pre_acc = inner_acc.accumulate(&prev_acc);
        inner_with_pre_acc.collapse();

        let mut accumulated = proof_acc.accumulate(&inner_with_pre_acc);
        accumulated.collapse();

        assert!(
            accumulated.check(&srs.s_g2().into(), &fixed_bases),
            "IVC acc verification failed"
        );

        println!("Asserted validity of state {:?}", state);

        // Set the new goals (public inputs) for the next iteration.
        state += F::ONE;
        acc = accumulated;
    }
}

fn main() {
    // test_certificate();
    // test_ivc();
    test_ivc_with_inner();
}
