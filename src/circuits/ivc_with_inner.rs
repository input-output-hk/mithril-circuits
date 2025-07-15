use crate::{
    Accumulator, ArithInstructions, AssignedAccumulator, AssignedVk, AssignmentInstructions,
    BinaryInstructions, Circuit, CircuitCurve, ComposableChip, ConstraintSystem, Error,
    EvaluationDomain, FieldChip, ForeignEccChip, ForeignEccConfig, Layouter, NB_ARITH_COLS,
    NB_POSEIDON_ADVICE_COLS, NB_POSEIDON_FIXED_COLS, NativeChip, NativeConfig, NativeGadget,
    P2RDecompositionChip, P2RDecompositionConfig, PoseidonChip, PoseidonConfig, Pow2RangeChip,
    PublicInputInstructions, SimpleFloorPlanner, Value, ZeroInstructions,
    nb_foreign_ecc_chip_columns, verifier, verifier::VerifierGadget,
};
use halo2curves::{CurveAffine, ff::Field, group::Group};
use midnight_circuits::types::AssignedForeignPoint;
use std::collections::HashSet;

type C = blstrs::G1Projective;
type CAffine = blstrs::G1Affine;
type E = blstrs::Bls12;
type CBase = <C as CircuitCurve>::Base;
type F = <CAffine as CurveAffine>::ScalarExt;

type NG = NativeGadget<F, P2RDecompositionChip<F>, NativeChip<F>>;

const NB_INNER_INSTANCES: usize = 1;
#[derive(Clone, Debug)]
pub struct IvcCircuit {
    pub self_vk: (EvaluationDomain<F>, ConstraintSystem<F>, Value<F>), // (domain, cs, vk_repr)
    // We use a simple application function that increases a counter.
    pub prev_state: Value<F>,
    pub prev_proof: Value<Vec<u8>>,
    pub prev_acc: Value<Accumulator<C>>,
    // inner circuit
    pub inner_vk: (EvaluationDomain<F>, ConstraintSystem<F>, Value<F>), // (domain, cs, vk_repr)
    pub inner_instances: Value<[F; NB_INNER_INSTANCES]>,
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
        let assigned_inner_vk: AssignedVk<C> = verifier_chip.assign_vk_as_public_input(
            &mut layouter,
            inner_vk_name,
            inner_domain,
            inner_cs,
            *inner_vk_value,
        )?;

        let assigned_inner_pi =
            scalar_chip.assign_many(&mut layouter, &self.inner_instances.transpose_array())?;

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
        let assigned_self_vk: AssignedVk<C> = verifier_chip.assign_vk_as_public_input(
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
            fixed_base_names.extend(verifier::fixed_base_names::<C>(
                self_vk_name,
                self_cs.num_fixed_columns() + self_cs.num_selectors(),
                self_cs.permutation().columns.len(),
            ));
            fixed_base_names.extend(verifier::fixed_base_names::<C>(
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
        let mut acc_with_inner = inner_proof_acc.accumulate(
            &mut layouter,
            &verifier_chip,
            &scalar_chip,
            &poseidon_chip,
            &prev_acc,
        )?;
        acc_with_inner.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        // Accumulate the `proof_acc` with the previous witnessed accumulator.
        // `next_acc` will satisfy the invariant iff both `proof_acc` and `prev_acc` do.
        let mut next_acc = proof_acc.accumulate(
            &mut layouter,
            &verifier_chip,
            &scalar_chip,
            &poseidon_chip,
            &acc_with_inner,
        )?;

        // Finally, collapse the resulting accumulator and constraint it as public.
        next_acc.collapse(&mut layouter, &curve_chip, &scalar_chip)?;

        verifier_chip.constrain_as_public_input(&mut layouter, &next_acc)
    }
}
