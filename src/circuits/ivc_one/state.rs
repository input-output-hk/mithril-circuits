use crate::{
    Accumulator, AssignedByte, AssignedNative, AssignedNativePoint, AssignedScalarOfNativeCurve,
    AssignedVk, Instantiable, Jubjub, KZGCommitmentScheme, PolynomialLabel, VerifyingKey,
    circuits::fixed_bases,
    ivc_one::{C, E, F, PREIMAGE_SIZE, S},
    schnorr_signature::{Signature as SchnorrSignature, VerificationKey as SchnorrVerificationKey},
};
use ff::Field;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct State {
    pub(crate) counter: F,
    pub(crate) msg: F,
    pub(crate) merkle_root: F,
    pub(crate) next_merkle_root: F,
    pub(crate) protocol_params: F,
    pub(crate) next_protocol_params: F,
    pub(crate) current_epoch: F,
}

impl State {
    pub fn new(
        counter: F,
        msg: F,
        merkle_root: F,
        next_merkle_root: F,
        protocol_params: F,
        next_protocol_params: F,
        current_epoch: F,
    ) -> Self {
        State {
            counter,
            msg,
            merkle_root,
            next_merkle_root,
            protocol_params,
            next_protocol_params,
            current_epoch,
        }
    }

    pub fn genesis() -> Self {
        State {
            counter: F::ZERO,
            msg: F::ZERO,
            merkle_root: F::ZERO,
            next_merkle_root: F::ZERO,
            protocol_params: F::ZERO,
            next_protocol_params: F::ZERO,
            current_epoch: F::ZERO,
        }
    }

    pub fn as_public_input(&self) -> Vec<F> {
        let state = self.clone();
        vec![
            state.counter,
            state.msg,
            state.merkle_root,
            state.next_merkle_root,
            state.protocol_params,
            state.next_protocol_params,
            state.current_epoch,
        ]
    }
}

/// In-circuit counterpart of [`State`].
#[derive(Clone, Debug)]
pub struct AssignedState {
    pub(crate) counter: AssignedNative<F>,
    pub(crate) msg: AssignedNative<F>,
    pub(crate) merkle_root: AssignedNative<F>,
    pub(crate) next_merkle_root: AssignedNative<F>,
    pub(crate) protocol_params: AssignedNative<F>,
    pub(crate) next_protocol_params: AssignedNative<F>,
    pub(crate) current_epoch: AssignedNative<F>,
}

impl AssignedState {
    pub fn as_public_input(&self) -> Vec<AssignedNative<F>> {
        let state = self.clone();
        vec![
            state.counter,
            state.msg,
            state.merkle_root,
            state.next_merkle_root,
            state.protocol_params,
            state.next_protocol_params,
            state.current_epoch,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct Global {
    // Persistent values that do not change through an ivc stream
    pub(crate) genesis_msg: F,
    pub(crate) genesis_vk: SchnorrVerificationKey,
    // Certificate verifying key
    pub(crate) cert_vk: VerifyingKey<F, KZGCommitmentScheme<E>>,
    // IVC verifying key
    pub(crate) self_vk: VerifyingKey<F, KZGCommitmentScheme<E>>,
}

impl Global {
    pub fn new(
        genesis_msg: F,
        genesis_vk: SchnorrVerificationKey,
        cert_vk: &VerifyingKey<F, KZGCommitmentScheme<E>>,
        self_vk: &VerifyingKey<F, KZGCommitmentScheme<E>>,
    ) -> Self {
        Global {
            genesis_msg,
            genesis_vk,
            cert_vk: cert_vk.clone(),
            self_vk: self_vk.clone(),
        }
    }

    pub fn as_public_input(&self) -> Vec<F> {
        [
            vec![self.genesis_msg],
            AssignedNativePoint::<Jubjub>::as_public_input(&self.genesis_vk.0),
            AssignedVk::<S>::as_public_input(&self.cert_vk),
            AssignedVk::<S>::as_public_input(&self.self_vk),
        ]
        .concat()
    }
}

#[derive(Clone, Debug)]
pub struct AssignedGlobal {
    //Persistent values that do not change through an ivc stream
    pub(crate) genesis_msg: AssignedNative<F>,
    pub(crate) genesis_vk: AssignedNativePoint<Jubjub>,
    pub(crate) cert_vk: AssignedVk<S>,
    pub(crate) self_vk: AssignedVk<S>,
    // Native (unprefixed) fixed base labels of cert_vk, in collapsed order
    pub(crate) cert_fixed_base_labels: Vec<PolynomialLabel>,
    // Combined fixed base labels for cert_vk (prefixed) and ivc_vk, in collapsed order
    pub(crate) fixed_base_labels: Vec<PolynomialLabel>,
}

#[derive(Clone, Debug)]
pub struct Witness {
    pub(crate) genesis_sig: SchnorrSignature,
    pub(crate) cert_msg: F,
    pub(crate) cert_merkle_root: F,
    // Protocol msg preimage bytes
    pub(crate) msg_preimage: [u8; PREIMAGE_SIZE],
}

impl Witness {
    pub fn new(
        genesis_sig: SchnorrSignature,
        cert_merkle_root: F,
        cert_msg: F,
        msg_preimage: [u8; PREIMAGE_SIZE],
    ) -> Self {
        Witness {
            genesis_sig,
            cert_merkle_root,
            cert_msg,
            msg_preimage,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedWitness {
    pub(crate) genesis_sig: (AssignedScalarOfNativeCurve<Jubjub>, AssignedNative<F>),
    pub(crate) cert_merkle_root: AssignedNative<F>,
    pub(crate) cert_msg: AssignedNative<F>,
    // Protocol msg preimage bytes
    pub(crate) msg_preimage: Vec<AssignedByte<F>>,
}

/// The trivial (identity) accumulator over the given fixed base labels. This
/// is the accumulator the IVC stream starts from.
///
/// The variable base of each side is the identity point with scalar 1: this
/// is what an in-circuit `prepare` of an empty proof, scaled by the bit 0 and
/// collapsed, evaluates to.
pub fn trivial_acc(fixed_base_labels: &[PolynomialLabel]) -> Accumulator<S> {
    Accumulator::<S>::trivial(fixed_base_labels)
}

/// The fixed bases of `vk` and their labels (sorted). With `Some(prefix)` the
/// labels are prefixed, see [`fixed_bases::relabel`].
pub fn fixed_bases_and_labels(
    prefix: Option<&str>,
    vk: &VerifyingKey<F, KZGCommitmentScheme<E>>,
) -> (BTreeMap<PolynomialLabel, C>, Vec<PolynomialLabel>) {
    let fixed_bases = fixed_bases::fixed_bases(prefix, vk);
    let fixed_base_labels = fixed_bases.keys().cloned().collect::<Vec<_>>();
    (fixed_bases, fixed_base_labels)
}
