//! Recursive certificate-chain verification, adapted from the main branch's IVC.
//!
//! Each step binds a signed protocol message to an epoch transition and folds
//! the certificate proof and previous IVC proof into a KZG accumulator.
//! Verifiers must check both the latest proof and its public accumulator.

use crate::{
    BlstrsEmulation, CircuitCurve, NativeChip, NativeGadget, P2RDecompositionChip, SelfEmulation,
};

pub type S = BlstrsEmulation;
pub type F = <S as SelfEmulation>::F;
pub type C = <S as SelfEmulation>::C;
pub type E = <S as SelfEmulation>::Engine;
type CBase = <C as CircuitCurve>::Base;
type NG = NativeGadget<F, P2RDecompositionChip<F>, NativeChip<F>>;

/// Row-domain size of the recursive circuit.
pub const K: u32 = 19;
/// Size of the protocol-message encoding inherited from the main branch.
pub const PREIMAGE_SIZE: usize = 190;

/// Certificate relation verified by every non-genesis step of an IVC stream.
/// Each variant requires its own IVC proving and verifying keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateVariant {
    /// Public inputs `(root, topic)`; the topic hashes the protocol message.
    TopicOnly,
    /// Public inputs `(root, topic, body)`; the body hashes the protocol message.
    TopicBody,
}

impl CertificateVariant {
    pub fn name(self) -> &'static str {
        match self {
            Self::TopicOnly => "topiconly",
            Self::TopicBody => "topicbody",
        }
    }

    /// Formats the corresponding inner certificate instance.
    pub fn certificate_instance(self, root: F, topic: F, msg: F) -> Vec<F> {
        match self {
            Self::TopicOnly => vec![root, topic],
            Self::TopicBody => vec![root, topic, msg],
        }
    }
}

/// Maps a supported certificate relation to its recursive public-input format.
pub trait IvcCertificate: crate::Relation<Error = crate::Error> {
    const VARIANT: CertificateVariant;
    fn instance(root: F, topic: F, msg: F) -> Self::Instance;
}

impl IvcCertificate for super::certificate_topiconly::Certificate {
    const VARIANT: CertificateVariant = CertificateVariant::TopicOnly;
    fn instance(root: F, topic: F, _msg: F) -> Self::Instance {
        (root, topic)
    }
}

impl IvcCertificate for super::certificate_topicbody::Certificate {
    const VARIANT: CertificateVariant = CertificateVariant::TopicBody;
    fn instance(root: F, topic: F, msg: F) -> Self::Instance {
        (root, topic, msg)
    }
}

pub mod circuit;
pub mod config;
pub mod fixed_bases;
pub mod gadget;
pub mod genesis_signature;
pub mod io;
pub mod message;
pub mod proof;
pub mod state;

#[cfg(test)]
mod tests;
