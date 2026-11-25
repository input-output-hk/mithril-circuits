//! Key generation, per-step proving, and full verification of an IVC artifact.
//!
//! Intermediate IVC proofs and certificate proofs use Poseidon transcripts.
//! A terminal IVC proof may use another transcript, such as Blake2b. A terminal
//! proof cannot be fed to another step unless it uses the Poseidon transcript.

use std::collections::BTreeMap;

use ff::Field;
use midnight_proofs::{
    plonk::ProvingKey,
    poly::kzg::params::ParamsVerifierKZG,
    transcript::{Hashable, Sampleable, TranscriptHash},
};
use rand_core::OsRng;

use super::{
    C, CertificateVariant, E, F, K, S,
    circuit::IvcCircuit,
    fixed_bases,
    state::{Global, State, Witness},
};
use crate::{
    Accumulator, AssignedAccumulator, CERT_VK_NAME, CircuitTranscript, DualMSM, Error,
    Instantiable, KZGCommitmentScheme, ParamsKZG, Point, PolynomialLabel, PoseidonState,
    Transcript, VerifyingKey, create_proof, keygen_pk, keygen_vk_with_k, prepare,
};

/// Proving material for one fixed certificate relation and variant.
pub struct IvcKeys {
    pub variant: CertificateVariant,
    pub vk: VerifyingKey<F, KZGCommitmentScheme<E>>,
    pub pk: ProvingKey<F, KZGCommitmentScheme<E>>,
    cert_vk: VerifyingKey<F, KZGCommitmentScheme<E>>,
}

impl IvcKeys {
    pub fn setup(
        params: &ParamsKZG<E>,
        cert_vk: &VerifyingKey<F, KZGCommitmentScheme<E>>,
        variant: CertificateVariant,
    ) -> Result<Self, Error> {
        let circuit = IvcCircuit::unknown(cert_vk, variant);
        let vk = keygen_vk_with_k(params, &circuit, K)?;
        let pk = keygen_pk(vk.clone(), &circuit)?;
        Ok(Self {
            variant,
            vk,
            pk,
            cert_vk: cert_vk.clone(),
        })
    }

    pub fn global(
        &self,
        genesis_msg: F,
        genesis_vk: super::genesis_signature::VerificationKey,
    ) -> Global {
        Global::new(genesis_msg, genesis_vk, &self.cert_vk, &self.vk)
    }
}

/// Output of a step. Verification also requires the trusted [`Global`] values.
#[derive(Clone, Debug)]
pub struct StepProof {
    pub state: State,
    pub accumulator: Accumulator<S>,
    pub proof: Vec<u8>,
}

/// Builds the complete public instance, including the accumulator's scalars.
pub fn public_inputs(global: &Global, state: &State, acc: &Accumulator<S>) -> Vec<F> {
    [
        global.as_public_input(),
        state.as_public_input(),
        AssignedAccumulator::as_public_input(acc),
    ]
    .concat()
}

/// Fixed commitment map pinned by the trusted certificate and IVC verifying keys.
pub fn combined_fixed_bases(global: &Global) -> BTreeMap<PolynomialLabel, C> {
    fixed_bases::combine_fixed_bases(&[
        &fixed_bases::fixed_bases(Some(CERT_VK_NAME), &global.cert_vk),
        &fixed_bases::fixed_bases(None, &global.self_vk),
    ])
}

pub fn initial_accumulator(global: &Global) -> Accumulator<S> {
    Accumulator::trivial(
        &combined_fixed_bases(global)
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
    )
}

// Labels are not part of the public-input encoding. Pin their exact layout to
// the one used by assign_collapsed_accumulator before interpreting any scalars.
fn check_accumulator_shape(acc: &Accumulator<S>, labels: &[PolynomialLabel]) -> Result<(), Error> {
    let lhs = acc.lhs();
    let rhs = acc.rhs();
    let rhs_bases = rhs.bases();
    let expected_rhs_labels = [labels, &[PolynomialLabel::NoLabel]].concat();
    if !matches!(lhs.bases().as_slice(), [Point::Variable(_)])
        || lhs.labels() != [PolynomialLabel::NoLabel]
        || lhs.scalars() != [F::ONE]
        || rhs_bases.len() != labels.len() + 1
        || !rhs_bases[..labels.len()]
            .iter()
            .all(|base| matches!(base, Point::Fixed))
        || !matches!(rhs_bases.last(), Some(Point::Variable(_)))
        || rhs.labels() != expected_rhs_labels
        || rhs.scalars().last() != Some(&F::ONE)
    {
        return Err(Error::InvalidInstances);
    }
    Ok(())
}

/// Prepares a proof using the same two instance columns as the standard library.
pub fn prepare_proof<H: TranscriptHash>(
    vk: &VerifyingKey<F, KZGCommitmentScheme<E>>,
    instance: &[F],
    proof: &[u8],
) -> Result<DualMSM<E>, Error>
where
    C: Hashable<H>,
    F: Hashable<H> + Sampleable<H>,
{
    let mut transcript = CircuitTranscript::<H>::init_from_bytes(proof);
    let result =
        prepare::<F, KZGCommitmentScheme<E>, _>(vk, &[], &[&[], instance], &mut transcript)?;
    transcript.assert_empty()?;
    Ok(result)
}

/// Verifies both the SNARK and the accumulator against explicitly trusted globals.
pub fn verify<H: TranscriptHash>(
    params: &ParamsVerifierKZG<E>,
    global: &Global,
    step: &StepProof,
) -> Result<(), Error>
where
    C: Hashable<H>,
    F: Hashable<H> + Sampleable<H>,
{
    let fixed = combined_fixed_bases(global);
    check_accumulator_shape(
        &step.accumulator,
        &fixed.keys().cloned().collect::<Vec<_>>(),
    )?;
    let instance = public_inputs(global, &step.state, &step.accumulator);
    let guard = prepare_proof::<H>(&global.self_vk, &instance, &step.proof)?;
    if !guard.check(params) || !step.accumulator.check(params, &fixed) {
        return Err(Error::Opening);
    }
    Ok(())
}

/// Produces one step, folding the previous proof and new certificate obligations.
/// At genesis, child proofs are absent and the authority signature roots the stream.
#[allow(clippy::too_many_arguments)]
pub fn prove_step<H: TranscriptHash>(
    params: &ParamsKZG<E>,
    keys: &IvcKeys,
    global: &Global,
    state: &State,
    witness: &Witness,
    cert_proof: &[u8],
    previous_proof: &[u8],
    acc: &Accumulator<S>,
) -> Result<StepProof, Error>
where
    C: Hashable<H>,
    F: Hashable<H> + Sampleable<H>,
{
    if global.cert_vk.transcript_repr() != keys.cert_vk.transcript_repr()
        || global.self_vk.transcript_repr() != keys.vk.transcript_repr()
    {
        return Err(Error::InvalidInstances);
    }
    let next_state = state.advance(keys.variant, global, witness)?;
    let fixed = combined_fixed_bases(global);
    check_accumulator_shape(acc, &fixed.keys().cloned().collect::<Vec<_>>())?;
    let cert_fixed = fixed_bases::fixed_bases(None, &keys.cert_vk);
    let self_fixed = fixed_bases::fixed_bases(None, &keys.vk);
    let (cert_acc, self_acc) = if state.counter == F::ZERO {
        (
            fixed_bases::relabel_acc(
                CERT_VK_NAME,
                &Accumulator::trivial(&cert_fixed.keys().cloned().collect::<Vec<_>>()),
            ),
            Accumulator::trivial(&self_fixed.keys().cloned().collect::<Vec<_>>()),
        )
    } else {
        let cert_instance = keys.variant.certificate_instance(
            witness.cert_merkle_root,
            witness.cert_topic,
            witness.cert_msg,
        );
        let cert_guard =
            prepare_proof::<PoseidonState<F>>(&keys.cert_vk, &cert_instance, cert_proof)?;
        let self_guard = prepare_proof::<PoseidonState<F>>(
            &keys.vk,
            &public_inputs(global, state, acc),
            previous_proof,
        )?;
        let verifier_params = params.verifier_params();
        if !cert_guard.clone().check(&verifier_params)
            || !self_guard.clone().check(&verifier_params)
        {
            return Err(Error::Opening);
        }
        let cert_acc = fixed_bases::collapsed_relabeled_acc(CERT_VK_NAME, cert_guard, &cert_fixed);
        let mut self_acc = Accumulator::from_dual_msm(self_guard, &self_fixed);
        self_acc.collapse();
        (cert_acc, self_acc)
    };
    if !acc.check(&params.verifier_params(), &fixed) {
        return Err(Error::Opening);
    }
    let mut next_acc = Accumulator::accumulate(&[acc.clone(), cert_acc, self_acc]);
    next_acc.collapse();
    let circuit = IvcCircuit::new(
        keys.variant,
        global.clone(),
        state.clone(),
        witness.clone(),
        cert_proof.to_vec(),
        previous_proof.to_vec(),
        acc.clone(),
        &keys.cert_vk,
        &keys.vk,
    );
    let instance = public_inputs(global, &next_state, &next_acc);
    let mut transcript = CircuitTranscript::<H>::init();
    create_proof::<F, KZGCommitmentScheme<E>, _, _>(
        params,
        &keys.pk,
        &circuit,
        0,
        &[&[], &instance],
        &mut transcript,
        OsRng,
    )?;
    Ok(StepProof {
        state: next_state,
        accumulator: next_acc,
        proof: transcript.finalize(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Msm;

    #[test]
    fn accumulator_labels_and_shape_are_pinned() {
        let labels = vec![
            PolynomialLabel::Custom("cert_vk/Fixed(0)".into()),
            PolynomialLabel::Fixed(0),
        ];
        let acc = Accumulator::<S>::trivial(&labels);
        assert!(check_accumulator_shape(&acc, &labels).is_ok());

        let rhs = acc.rhs();
        let mut changed = rhs.labels();
        changed.swap(0, 1);
        let swapped = Accumulator::new(acc.lhs(), Msm::new(&rhs.bases(), &rhs.scalars(), &changed));
        assert!(check_accumulator_shape(&swapped, &labels).is_err());
        changed[0] = PolynomialLabel::Custom("unknown fixed base".into());
        let unknown = Accumulator::new(acc.lhs(), Msm::new(&rhs.bases(), &rhs.scalars(), &changed));
        assert!(check_accumulator_shape(&unknown, &labels).is_err());

        let mut scalars = rhs.scalars();
        *scalars.last_mut().unwrap() = F::from(2);
        let scaled = Accumulator::new(acc.lhs(), Msm::new(&rhs.bases(), &scalars, &rhs.labels()));
        assert!(check_accumulator_shape(&scaled, &labels).is_err());
        assert!(check_accumulator_shape(&Accumulator::trivial(&[]), &labels).is_err());
    }
}
