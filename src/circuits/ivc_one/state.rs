use crate::{
    Accumulator, AssignedByte, AssignedNative, AssignedNativePoint, AssignedScalarOfNativeCurve,
    AssignedVk, Instantiable, Jubjub, KZGCommitmentScheme, PolynomialLabel, VerifyingKey,
    ivc_one::fixed_bases,
    ivc_one::genesis_signature::{
        Signature as SchnorrSignature, VerificationKey as SchnorrVerificationKey,
    },
    ivc_one::{C, E, F, PREIMAGE_SIZE, S},
};
use ff::Field;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub counter: F,
    /// Signed topic. In topic-only mode this equals `msg`.
    pub topic: F,
    /// Protocol-message hash: the topic in topic-only mode, the body otherwise.
    pub msg: F,
    pub merkle_root: F,
    pub next_merkle_root: F,
    pub protocol_params: F,
    pub next_protocol_params: F,
    pub current_epoch: F,
}

impl State {
    pub fn new(
        counter: F,
        topic: F,
        msg: F,
        merkle_root: F,
        next_merkle_root: F,
        protocol_params: F,
        next_protocol_params: F,
        current_epoch: F,
    ) -> Self {
        State {
            counter,
            topic,
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
            topic: F::ZERO,
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
            state.topic,
            state.msg,
            state.merkle_root,
            state.next_merkle_root,
            state.protocol_params,
            state.next_protocol_params,
            state.current_epoch,
        ]
    }

    /// Computes the next public state and checks the native form of the transition.
    pub fn advance(
        &self,
        variant: super::CertificateVariant,
        global: &Global,
        witness: &Witness,
    ) -> Result<Self, crate::Error> {
        use super::{CertificateVariant, message::ProtocolMessage};
        let invalid = |reason: &str| crate::Error::Synthesis(reason.into());
        let genesis = self.counter == F::ZERO;
        let message = ProtocolMessage::from_preimage(&witness.msg_preimage)?;
        let msg = if genesis {
            global.genesis_msg
        } else {
            witness.cert_msg
        };
        let topic = if genesis {
            global.genesis_msg
        } else {
            witness.cert_topic
        };
        if message.hash() != msg {
            return Err(invalid(
                "protocol-message preimage does not match the signed message",
            ));
        }
        if variant == CertificateVariant::TopicOnly && topic != msg {
            return Err(invalid(
                "topic-only certificate topic must hash the protocol message",
            ));
        }
        if genesis {
            witness
                .genesis_sig
                .verify(&[msg], &global.genesis_vk)
                .map_err(|_| invalid("invalid IVC genesis signature"))?;
        }
        let epoch = F::from(message.current_epoch);
        let same_epoch = epoch == self.current_epoch;
        let next_epoch = epoch == self.current_epoch + F::ONE;
        if self.counter == F::ONE && !next_epoch {
            return Err(invalid(
                "the first certificate after genesis must advance one epoch",
            ));
        }
        if !genesis {
            if !((same_epoch && witness.cert_merkle_root == self.merkle_root)
                || (next_epoch && witness.cert_merkle_root == self.next_merkle_root))
            {
                return Err(invalid(
                    "invalid certificate epoch or registry-root handoff",
                ));
            }
            if same_epoch
                && (message.next_merkle_root != self.next_merkle_root
                    || message.next_protocol_params != self.next_protocol_params)
            {
                return Err(invalid(
                    "next-epoch registry and parameters must stay fixed within an epoch",
                ));
            }
        }
        Ok(Self {
            counter: self.counter + F::ONE,
            topic,
            msg,
            merkle_root: if genesis {
                F::ZERO
            } else {
                witness.cert_merkle_root
            },
            next_merkle_root: message.next_merkle_root,
            protocol_params: if genesis {
                F::ZERO
            } else if same_epoch {
                self.protocol_params
            } else {
                self.next_protocol_params
            },
            next_protocol_params: message.next_protocol_params,
            current_epoch: epoch,
        })
    }
}

/// In-circuit counterpart of [`State`].
#[derive(Clone, Debug)]
pub struct AssignedState {
    pub(crate) counter: AssignedNative<F>,
    pub(crate) topic: AssignedNative<F>,
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
            state.topic,
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
    pub genesis_msg: F,
    pub genesis_vk: SchnorrVerificationKey,
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
    pub genesis_sig: SchnorrSignature,
    pub cert_topic: F,
    pub cert_msg: F,
    pub cert_merkle_root: F,
    // Protocol msg preimage bytes
    pub msg_preimage: [u8; PREIMAGE_SIZE],
}

impl Witness {
    pub fn new(
        genesis_sig: SchnorrSignature,
        cert_merkle_root: F,
        cert_topic: F,
        cert_msg: F,
        msg_preimage: [u8; PREIMAGE_SIZE],
    ) -> Self {
        Witness {
            genesis_sig,
            cert_topic,
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
    pub(crate) cert_topic: AssignedNative<F>,
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
