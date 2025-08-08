use crate::{
    Accumulator, ArithInstructions, AssignedAccumulator, AssignedVk, AssignmentInstructions,
    BinaryInstructions, BlstrsEmulation, Circuit, CircuitCurve, ComposableChip, ConstraintSystem,
    Error, EvaluationDomain, FieldChip, ForeignEccChip, ForeignEccConfig, Layouter, NB_ARITH_COLS,
    NB_POSEIDON_ADVICE_COLS, NB_POSEIDON_FIXED_COLS, NativeChip, NativeConfig, NativeGadget,
    P2RDecompositionChip, P2RDecompositionConfig, PoseidonChip, PoseidonConfig, Pow2RangeChip,
    PublicInputInstructions, SelfEmulation, SimpleFloorPlanner, Value, ZeroInstructions,
    nb_foreign_ecc_chip_columns, verifier, verifier::VerifierGadget,
};
use halo2curves::{ff::Field, group::Group};
use midnight_circuits::types::AssignedForeignPoint;
use std::collections::HashSet;

type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;

type E = <S as SelfEmulation>::Engine;
type CBase = <C as CircuitCurve>::Base;

type NG = NativeGadget<F, P2RDecompositionChip<F>, NativeChip<F>>;

const NB_INNER_INSTANCES: usize = 2;
#[derive(Clone, Debug)]
pub struct IvcCircuit {
    pub self_vk: (EvaluationDomain<F>, ConstraintSystem<F>, Value<F>), // (domain, cs, vk_repr)
    // We use a simple application function that increases a counter.
    pub prev_state: Value<F>,
    pub prev_proof: Value<Vec<u8>>,
    pub prev_acc: Value<Accumulator<S>>,
    // inner circuit
    pub inner_vk: (EvaluationDomain<F>, ConstraintSystem<F>, Value<F>), // (domain, cs, vk_repr)
    pub inner_instances: Value<Vec<F>>,
    pub inner_proof: Value<Vec<u8>>,
}

pub fn configure_ivc_circuit(
    meta: &mut ConstraintSystem<F>,
) -> (
    NativeConfig,
    P2RDecompositionConfig,
    ForeignEccConfig<C>,
    PoseidonConfig<F>,
) {
    let nb_advice_cols = nb_foreign_ecc_chip_columns::<F, C, C, NG>();
    let nb_fixed_cols = NB_ARITH_COLS + 4;

    let advice_columns: Vec<_> = (0..nb_advice_cols).map(|_| meta.advice_column()).collect();
    let fixed_columns: Vec<_> = (0..nb_fixed_cols).map(|_| meta.fixed_column()).collect();
    let committed_instance_column = meta.instance_column();
    let instance_column = meta.instance_column();

    let native_config = NativeChip::configure(
        meta,
        &(
            advice_columns[..NB_ARITH_COLS].try_into().unwrap(),
            fixed_columns[..NB_ARITH_COLS + 4].try_into().unwrap(),
            [committed_instance_column, instance_column],
        ),
    );
    let core_decomp_config = {
        let pow2_config = Pow2RangeChip::configure(meta, &advice_columns[1..NB_ARITH_COLS]);
        P2RDecompositionChip::configure(meta, &(native_config.clone(), pow2_config))
    };

    let base_config = FieldChip::<F, CBase, C, NG>::configure(meta, &advice_columns);
    let curve_config =
        ForeignEccChip::<F, C, C, NG, NG>::configure(meta, &base_config, &advice_columns);

    let poseidon_config = PoseidonChip::configure(
        meta,
        &(
            advice_columns[..NB_POSEIDON_ADVICE_COLS]
                .try_into()
                .unwrap(),
            fixed_columns[..NB_POSEIDON_FIXED_COLS].try_into().unwrap(),
        ),
    );

    (
        native_config,
        core_decomp_config,
        curve_config,
        poseidon_config,
    )
}

impl Circuit<F> for IvcCircuit {
    type Config = (
        NativeConfig,
        P2RDecompositionConfig,
        ForeignEccConfig<C>,
        PoseidonConfig<F>,
    );
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unreachable!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        configure_ivc_circuit(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let native_chip = <NativeChip<F> as ComposableChip<F>>::new(&config.0, &());
        let core_decomp_chip = P2RDecompositionChip::new(&config.1, &16);
        let scalar_chip = NativeGadget::new(core_decomp_chip.clone(), native_chip.clone());
        let curve_chip = { ForeignEccChip::new(&config.2, &scalar_chip, &scalar_chip) };
        let poseidon_chip = PoseidonChip::new(&config.3, &native_chip);

        let verifier_chip = VerifierGadget::new(&curve_chip, &scalar_chip, &poseidon_chip);

        core_decomp_chip.load(&mut layouter)?;

        let id_point: AssignedForeignPoint<_, _, _> =
            curve_chip.assign_fixed(&mut layouter, C::identity())?;

        // assign for inner circuit proof verification
        let inner_vk_name = "inner_vk";
        let (inner_domain, inner_cs, inner_vk_value) = &self.inner_vk;
        let assigned_inner_vk: AssignedVk<S> = verifier_chip.assign_vk_as_public_input(
            &mut layouter,
            inner_vk_name,
            inner_domain,
            inner_cs,
            *inner_vk_value,
        )?;

        let assigned_inner_pi = scalar_chip.assign_many(
            &mut layouter,
            &self
                .inner_instances
                .clone()
                .transpose_vec(NB_INNER_INSTANCES),
        )?;

        let mut inner_proof_acc = verifier_chip.prepare(
            &mut layouter,
            &assigned_inner_vk,
            &[("com_instance", id_point.clone())],
            &[&assigned_inner_pi],
            self.inner_proof.clone(),
        )?;

        inner_proof_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        // assign for self proof verification
        let self_vk_name = "self_vk";
        let (self_domain, self_cs, self_vk_value) = &self.self_vk;
        let assigned_self_vk: AssignedVk<S> = verifier_chip.assign_vk_as_public_input(
            &mut layouter,
            self_vk_name,
            self_domain,
            self_cs,
            *self_vk_value,
        )?;

        // Witness a previous state and update it in-circuit.
        // Then, constrain the new state as a public input.
        let prev_state = scalar_chip.assign(&mut layouter, self.prev_state)?;
        let next_state = scalar_chip.add_constant(&mut layouter, &prev_state, F::ONE)?;
        scalar_chip.constrain_as_public_input(&mut layouter, &next_state)?;

        // Witness a proof and an accumulator that ensure the validity of `prev_state`.
        let prev_acc = {
            let mut fixed_base_names = vec![String::from("com_instance")];
            fixed_base_names.extend(verifier::fixed_base_names::<S>(
                self_vk_name,
                self_cs.num_fixed_columns() + self_cs.num_selectors(),
                self_cs.permutation().columns.len(),
            ));
            fixed_base_names.extend(verifier::fixed_base_names::<S>(
                inner_vk_name,
                inner_cs.num_fixed_columns() + inner_cs.num_selectors(),
                inner_cs.permutation().columns.len(),
            ));
            // remove repeated names
            let mut seen = HashSet::new();
            fixed_base_names.retain(|x| seen.insert(x.clone()));
            AssignedAccumulator::assign(
                &mut layouter,
                &curve_chip,
                &scalar_chip,
                1,
                1,
                &[],
                &fixed_base_names,
                self.prev_acc.clone(),
            )?
        };

        let assigned_pi = [
            verifier_chip.as_public_input(&mut layouter, &assigned_inner_vk)?,
            verifier_chip.as_public_input(&mut layouter, &assigned_self_vk)?,
            vec![prev_state.clone()],
            verifier_chip.as_public_input(&mut layouter, &prev_acc)?,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        // Verify a witnessed proof that ensures the validity of `prev_state`.
        // The proof is valid iff `proof_acc` satisfies the invariant.
        let mut proof_acc = verifier_chip.prepare(
            &mut layouter,
            &assigned_self_vk,
            &[("com_instance", id_point)],
            &[&assigned_pi],
            self.prev_proof.clone(),
        )?;

        // If `prev_state` is genesis, we allow the prover to change the (probably
        // invalid) accumulator by a default accumulator that satisfies the invariant.
        let is_genesis = scalar_chip.is_zero(&mut layouter, &prev_state)?;
        let is_not_genesis = scalar_chip.not(&mut layouter, &is_genesis)?;

        AssignedAccumulator::scale_by_bit(
            &mut layouter,
            &scalar_chip,
            &is_not_genesis,
            &mut proof_acc,
        )?;

        proof_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        // Accumulate the inner_proof_acc
        let mut acc_with_inner = AssignedAccumulator::<S>::accumulate(
            &mut layouter,
            &verifier_chip,
            &scalar_chip,
            &poseidon_chip,
            &[inner_proof_acc, prev_acc],
        )?;
        acc_with_inner.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        // Accumulate the `proof_acc` with the previous witnessed accumulator.
        // `next_acc` will satisfy the invariant iff both `proof_acc` and `prev_acc` do.
        let mut next_acc = AssignedAccumulator::<S>::accumulate(
            &mut layouter,
            &verifier_chip,
            &scalar_chip,
            &poseidon_chip,
            &[proof_acc, acc_with_inner],
        )?;
        // Finally, collapse the resulting accumulator and constraint it as public.
        next_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        verifier_chip.constrain_as_public_input(&mut layouter, &next_acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::*;
    use crate::merkle_tree::{MTLeaf, MerklePath, MerkleTree};
    use crate::{
        AssignedNative, Bls12, CircuitTranscript, Instantiable, KZGCommitmentScheme, MerkleRoot,
        Msg, Msm, ParamsKZG, PoseidonState, Signature, SigningKey, Transcript, VerificationKey,
        create_proof, keygen_pk, keygen_vk_with_k, prepare,
    };
    use crate::{certificate::Certificate, compact_std_lib};
    use midnight_circuits::compact_std_lib::Relation;
    use midnight_circuits::testing_utils::plonk_api::filecoin_srs;
    use midnight_proofs::dev::CircuitCost;
    use midnight_proofs::utils::SerdeFormat;
    use rand_core::OsRng;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::BufReader;
    use std::time::Instant;

    fn open(k: u32) -> ParamsKZG<Bls12> {
        let path = format!("examples/assets/params_kzg_unsafe_{}", k);
        let file = File::open(path).unwrap();
        let mut reader = BufReader::new(file);
        let params: ParamsKZG<Bls12> =
            ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap();

        params
    }

    fn create_merkle_tree(n: usize) -> (Vec<SigningKey>, Vec<MTLeaf>, MerkleTree) {
        //  let mut rng = ChaCha20Rng::seed_from_u64(1234);
        let mut rng = OsRng;

        let mut sks = Vec::new();
        let mut leaves = Vec::new();
        for i in 0..n {
            let sk = SigningKey::generate(&mut rng);
            let vk = VerificationKey::from(&sk); // Replace this with actual initialization if provided
            leaves.push(MTLeaf(vk, -F::ONE));
            sks.push(sk);
        }
        let tree = MerkleTree::create(&leaves);

        (sks, leaves, tree)
    }

    fn setup_certificate() -> (
        Certificate,
        (MerkleRoot, Msg),
        Vec<(MTLeaf, MerklePath, Signature, u32)>,
    ) {
        let num_signers: usize = 3000;
        let depth = num_signers.next_power_of_two().trailing_zeros();
        let quorum = 3;
        let num_lotteries = quorum * 10;
        let relation = Certificate::new(quorum, num_lotteries, depth);
        println!("Circuit {:?}", relation);

        let (sks, leaves, merkle_tree) = create_merkle_tree(num_signers);
        let merkle_root = merkle_tree.root();
        // message to be signed
        let msg = F::from(42);

        // take the first few signers
        let mut witness = vec![];
        for i in 0..quorum as usize {
            let usk = sks[i].clone();
            let uvk = leaves[i].0;
            let sig = usk.sign(msg, &mut OsRng);
            sig.verify(msg, &uvk).unwrap();

            let merkle_path = merkle_tree.get_path(i);
            let computed_root = merkle_path.compute_root(leaves[i]);
            assert_eq!(merkle_root, computed_root);

            // any index is eligible as target is set to be the maximum
            witness.push((leaves[i], merkle_path, sig, (i + 1) as u32));
        }

        let instance = (merkle_root, msg);

        (relation, instance, witness)
    }

    #[test]
    fn test_ivc_with_inner() {
        const K: u32 = 20;

        // create unsafe parameters once
        // create(K);
        let srs = open(K);

        // set up inner circuit
        println!("setting up inner circuit...");
        const K_INNER: u32 = 13;
        let mut inner_srs = srs.clone();
        inner_srs.downsize(K_INNER);

        let (inner_relation, inner_instance, inner_witness) = setup_certificate();
        let inner_instance_vec = Certificate::format_instance(&inner_instance);
        let start = Instant::now();
        let inner_vk = compact_std_lib::setup_vk(&inner_srs, &inner_relation);
        let inner_pk = compact_std_lib::setup_pk(&inner_relation, &inner_vk);
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("inner circuit vk pk generation took: {:?}", duration);

        let start = Instant::now();
        let inner_proof = compact_std_lib::prove::<Certificate, PoseidonState<F>>(
            &inner_srs,
            &inner_pk,
            &inner_relation,
            &inner_instance,
            inner_witness,
            OsRng,
        )
        .expect("Proof generation should not fail");
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("Inner circuit proof generation took: {:?}", duration);

        let inner_dual_msm = {
            let mut transcript =
                CircuitTranscript::<PoseidonState<F>>::init_from_bytes(&inner_proof);
            prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
                inner_vk.vk(),
                &[&[C::identity()]],
                &[&[&inner_instance_vec]],
                &mut transcript,
            )
            .expect("Problem preparing the inner proof")
        };
        assert!(inner_dual_msm.clone().check(&inner_srs.verifier_params()));

        let mut inner_fixed_bases = BTreeMap::new();
        inner_fixed_bases.insert(String::from("com_instance"), C::identity());
        inner_fixed_bases.extend(verifier::fixed_bases::<S>("inner_vk", &inner_vk.vk()));

        let mut inner_acc: Accumulator<S> = inner_dual_msm.into();
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
            inner_instances: Value::known(inner_instance_vec.clone()),
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
        self_fixed_bases.extend(verifier::fixed_bases::<S>("self_vk", &vk));
        let self_fixed_base_names = self_fixed_bases.keys().cloned().collect::<Vec<_>>();

        let mut fixed_bases = BTreeMap::new();
        fixed_bases.extend(inner_fixed_bases.clone());
        fixed_bases.extend(self_fixed_bases.clone());
        let fixed_base_names = fixed_bases.keys().cloned().collect::<Vec<_>>();

        let trivial_acc = Accumulator::<S>::new(
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

        let self_trivial_acc = Accumulator::<S>::new(
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
        let mut inner_with_trivial_acc = Accumulator::accumulate(&[inner_acc.clone(), trivial_acc]);
        inner_with_trivial_acc.collapse();
        //

        assert!(
            inner_with_trivial_acc.check(&srs.s_g2().into(), &fixed_bases),
            "IVC acc verification failed"
        );

        let mut acc = Accumulator::accumulate(&[self_trivial_acc, inner_with_trivial_acc]);
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
                inner_instances: Value::known(inner_instance_vec.clone()),
                inner_proof: Value::known(inner_proof.clone()),
            };

            let mut public_inputs = AssignedVk::<S>::as_public_input(&inner_vk.vk());
            public_inputs.extend(AssignedVk::<S>::as_public_input(&vk));
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

            let proof_acc: Accumulator<S> = {
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

                let mut proof_acc: Accumulator<S> = dual_msm.into();
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
            let mut inner_with_pre_acc =
                Accumulator::accumulate(&[inner_acc.clone(), prev_acc.clone()]);
            inner_with_pre_acc.collapse();

            let mut accumulated = Accumulator::accumulate(&[proof_acc, inner_with_pre_acc]);
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
}
