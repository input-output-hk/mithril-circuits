//! Helpers for folding proofs of *several* circuits into one KZG accumulator.
//!
//! `midnight-circuits` identifies the fixed bases of an accumulator (the
//! fixed-column and permutation commitments of a verifying key, plus the
//! negated generator used by the KZG opening argument) by [`PolynomialLabel`]:
//! `Fixed(i)`, `PermutationFixed(i)` and `Custom("-G")`. Those labels only
//! identify a commitment *relative to one verifying key*: the `i`-th fixed
//! commitment of the certificate circuit and the `i`-th fixed commitment of
//! the IVC circuit both carry the label `Fixed(i)` although they are different
//! points.
//!
//! The IVC circuits of this crate fold, into a single accumulator, proofs of
//! the certificate circuit *and* proofs of the IVC circuit itself. The fixed
//! bases of one of the two verifying keys therefore have to be re-labelled
//! before the accumulators are combined. We prefix the labels of the
//! certificate verifying key ([`relabel`]) and keep the native labels for the
//! IVC verifying key, exactly as `midnight-aggregation` does for a single key.
//! `Custom("-G")` denotes the same point for every verifying key and is never
//! prefixed.
//!
//! Off-circuit the re-labelling is a pure renaming ([`relabel_acc`]). In
//! circuit, the labels of an [`AssignedAccumulator`] are not mutable through
//! the public API, so [`relabel_collapsed_acc`] witnesses a fresh accumulator
//! with the new labels and constrains its points and scalars to be equal to
//! the original ones.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Accumulator, AssertionInstructions, AssignedAccumulator, AssignedVk, BlstrsEmulation,
    ConstraintSystem, DualMSM, Error, EvaluationDomain, ForeignEccChip, InnerValue,
    KZGCommitmentScheme, Layouter, Msm, NativeChip, NativeGadget, P2RDecompositionChip, Point,
    PolynomialLabel, PublicInputInstructions, SelfEmulation, Value, VerifierGadget,
    VerifyingKey, verifier,
};

type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;
type E = <S as SelfEmulation>::Engine;
type NG = NativeGadget<F, P2RDecompositionChip<F>, NativeChip<F>>;
type CurveChip = ForeignEccChip<F, C, C, NG, NG>;

/// Label that `midnight-circuits` gives to the negated generator introduced by
/// the KZG multi-open argument. It is the same point for every verifying key.
const NEG_GENERATOR_LABEL: &str = "-G";

fn is_shared_label(label: &PolynomialLabel) -> bool {
    matches!(label, PolynomialLabel::Custom(name) if name == NEG_GENERATOR_LABEL)
}

/// Prefixes `label` so that it cannot collide with the equally named label of
/// another verifying key. The shared negated-generator label is returned
/// unchanged.
pub fn relabel(prefix: &str, label: &PolynomialLabel) -> PolynomialLabel {
    if is_shared_label(label) {
        label.clone()
    } else {
        PolynomialLabel::Custom(format!("{prefix}/{label:?}"))
    }
}

/// Applies [`relabel`] to every label of `labels`, preserving the order.
pub fn relabel_all(prefix: &str, labels: &[PolynomialLabel]) -> Vec<PolynomialLabel> {
    labels.iter().map(|label| relabel(prefix, label)).collect()
}

/// Applies [`relabel`] to the labels of the *fixed* terms of `msm`. Variable
/// terms keep their label. The order of the terms is preserved.
pub fn relabel_msm(prefix: &str, msm: &Msm<S>) -> Msm<S> {
    let bases = msm.bases();
    let scalars = msm.scalars();
    let labels: Vec<_> = msm
        .labels()
        .iter()
        .zip(bases.iter())
        .map(|(label, base)| match base {
            Point::Fixed => relabel(prefix, label),
            Point::Variable(_) => label.clone(),
        })
        .collect();
    Msm::new(&bases, &scalars, &labels)
}

/// Applies [`relabel_msm`] to both sides of `acc`.
///
/// Order matters: `collapse` sorts the fixed terms of an accumulator by label,
/// and the accumulation challenge is a hash over the accumulator's terms in
/// that order. The in-circuit accumulator is collapsed while it still carries
/// the native labels ([`relabel_collapsed_acc`]), so off-circuit an accumulator
/// must be collapsed *before* it is re-labelled, never after. Prefer
/// [`collapsed_relabeled_acc`], which does both in the right order.
pub fn relabel_acc(prefix: &str, acc: &Accumulator<S>) -> Accumulator<S> {
    Accumulator::new(
        relabel_msm(prefix, &acc.lhs()),
        relabel_msm(prefix, &acc.rhs()),
    )
}

/// Converts the dual MSM of an (off-circuit) verified proof into a collapsed
/// accumulator whose fixed bases carry the `prefix`-ed labels.
///
/// `native_fixed_bases` are the fixed bases of the proof's verifying key with
/// their native labels ([`fixed_bases`] with `None`). The accumulator is
/// collapsed before being re-labelled, so that its terms are in the same order
/// as those of the in-circuit accumulator produced by `prepare`, `collapse` and
/// [`relabel_collapsed_acc`]; see [`relabel_acc`].
pub fn collapsed_relabeled_acc(
    prefix: &str,
    dual_msm: DualMSM<E>,
    native_fixed_bases: &BTreeMap<PolynomialLabel, C>,
) -> Accumulator<S> {
    let mut acc = Accumulator::<S>::from_dual_msm(dual_msm, native_fixed_bases);
    acc.collapse();
    relabel_acc(prefix, &acc)
}

/// The fixed bases of `vk`, keyed by label. With `Some(prefix)` the labels are
/// passed through [`relabel`].
pub fn fixed_bases(
    prefix: Option<&str>,
    vk: &VerifyingKey<F, KZGCommitmentScheme<E>>,
) -> BTreeMap<PolynomialLabel, C> {
    let bases = verifier::fixed_bases::<S>(vk);
    match prefix {
        None => bases,
        Some(prefix) => bases
            .iter()
            .map(|(label, point)| (relabel(prefix, label), *point))
            .collect(),
    }
}

/// The (native) labels of the fixed bases of a circuit with constraint system
/// `cs`, in the order in which a collapsed accumulator over that circuit alone
/// lists them (sorted by label).
pub fn fixed_base_labels(cs: &ConstraintSystem<F>) -> Vec<PolynomialLabel> {
    verifier::fixed_base_labels::<S>(cs)
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Union of several label lists in the order in which a collapsed accumulator
/// holding all of them lists its fixed terms (sorted, without duplicates).
pub fn combine_labels(label_sets: &[&[PolynomialLabel]]) -> Vec<PolynomialLabel> {
    label_sets
        .iter()
        .flat_map(|labels| labels.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Union of several fixed-base maps.
///
/// # Panics
///
/// If a label present in several maps is mapped to different points.
pub fn combine_fixed_bases(
    maps: &[&BTreeMap<PolynomialLabel, C>],
) -> BTreeMap<PolynomialLabel, C> {
    let mut combined = BTreeMap::new();
    for map in maps {
        for (label, point) in map.iter() {
            if let Some(previous) = combined.insert(label.clone(), *point) {
                assert_eq!(
                    previous, *point,
                    "fixed base {label:?} is mapped to different points"
                );
            }
        }
    }
    combined
}

/// In-circuit analogue of [`relabel_acc`] for a *collapsed* accumulator.
///
/// `acc` must be the output of `AssignedAccumulator::collapse` (one variable
/// term labelled `NoLabel` on each side, plus one fixed term per label of
/// `fixed_base_labels` on the right-hand side). `fixed_base_labels` are the
/// native labels of the verifying key the accumulator was derived from, as
/// returned by [`fixed_base_labels`].
///
/// A fresh accumulator whose fixed terms carry the prefixed labels is
/// witnessed, and its public-input representation (the coordinates of the
/// variable points and all the scalars) is constrained to be equal to that of
/// `acc`. Labels are not part of that representation: they only tell the
/// off-circuit verifier which fixed base each scalar multiplies. Since the
/// prefixed labels are mapped to the very same points as the native ones (see
/// [`fixed_bases`]), the returned accumulator satisfies the pairing invariant
/// if and only if `acc` does.
pub fn relabel_collapsed_acc(
    layouter: &mut impl Layouter<F>,
    verifier_gadget: &VerifierGadget<S>,
    _curve_chip: &CurveChip,
    scalar_chip: &NG,
    prefix: &str,
    fixed_base_labels: &[PolynomialLabel],
    acc: &AssignedAccumulator<S>,
) -> Result<AssignedAccumulator<S>, Error> {
    let relabeled_labels = relabel_all(prefix, fixed_base_labels);
    let relabeled_value = acc.value().map(|acc| relabel_acc(prefix, &acc));

    let relabeled_acc = verifier_gadget.assign_collapsed_accumulator(
        layouter,
        &relabeled_labels,
        relabeled_value,
    )?;

    let original_pi = verifier_gadget.as_public_input(layouter, acc)?;
    let relabeled_pi = verifier_gadget.as_public_input(layouter, &relabeled_acc)?;
    assert_eq!(
        original_pi.len(),
        relabeled_pi.len(),
        "relabel_collapsed_acc: the accumulator is not in collapsed form"
    );
    for (original, relabeled) in original_pi.iter().zip(relabeled_pi.iter()) {
        scalar_chip.assert_equal(layouter, original, relabeled)?;
    }

    Ok(relabeled_acc)
}

/// Assigns a public VK while retaining the fixed domain of these IVC circuits.
/// Upstream now exposes k and omega as public inputs and requires the caller
/// to constrain them; they must not be chosen independently of this layout.
pub fn assign_vk(
    layouter: &mut impl Layouter<F>,
    verifier_gadget: &VerifierGadget<S>,
    scalar_chip: &NG,
    domain: &EvaluationDomain<F>,
    cs: &ConstraintSystem<F>,
    vk: Value<&VerifyingKey<F, KZGCommitmentScheme<E>>>,
) -> Result<AssignedVk<S>, Error> {
    let assigned = verifier_gadget.assign_vk_as_public_input(layouter, vk, cs)?;
    scalar_chip.assert_equal_to_fixed(layouter, assigned.k(), F::from(domain.k() as u64))?;
    scalar_chip.assert_equal_to_fixed(layouter, assigned.omega(), domain.get_omega())?;
    Ok(assigned)
}
