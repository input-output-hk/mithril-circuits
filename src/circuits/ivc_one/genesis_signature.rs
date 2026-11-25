//! The main branch's Schnorr authority signature for the IVC genesis message.
//!
//! Certificate signers use the compact tag-bearing scheme in
//! [`crate::schnorr_signature`]. The genesis authority uses this separate
//! domain-separated proof of knowledge, with response `s = r - c * sk`.

use crate::{
    DST_SCHNORR_SIGNATURE, HashCPU, JubjubBase, JubjubScalar, JubjubSubgroup, PoseidonHash,
    SignatureError,
    utils::{get_coordinates, jubjub_base_to_scalar},
};
use ff::Field;
use group::Group;
use rand_core::{CryptoRng, RngCore};

/// Secret scalar held by the genesis authority.
#[derive(Debug, Clone)]
pub struct SigningKey(JubjubScalar);

impl SigningKey {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(JubjubScalar::random(rng))
    }

    /// Signs the genesis protocol-message hash with a fresh nonce.
    pub fn sign(&self, msg: &[JubjubBase], rng: &mut (impl RngCore + CryptoRng)) -> Signature {
        let g = JubjubSubgroup::generator();
        let vk = g * self.0;
        let r = JubjubScalar::random(rng);
        let (vk_x, vk_y) = get_coordinates(vk);
        let (r_x, r_y) = get_coordinates(g * r);
        let mut transcript = vec![DST_SCHNORR_SIGNATURE, vk_x, vk_y, r_x, r_y];
        transcript.extend_from_slice(msg);
        let c = PoseidonHash::hash(&transcript);
        Signature {
            s: r - self.0 * jubjub_base_to_scalar(c),
            c,
        }
    }
}

/// Public key trusted for an IVC stream's genesis certificate.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerificationKey(pub JubjubSubgroup);

impl From<&SigningKey> for VerificationKey {
    fn from(sk: &SigningKey) -> Self {
        Self(JubjubSubgroup::generator() * sk.0)
    }
}

/// Randomized Schnorr proof over the genesis message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signature {
    pub s: JubjubScalar,
    pub c: JubjubBase,
}

impl Signature {
    pub fn verify(&self, msg: &[JubjubBase], vk: &VerificationKey) -> Result<(), SignatureError> {
        let r = JubjubSubgroup::generator() * self.s + vk.0 * jubjub_base_to_scalar(self.c);
        let (vk_x, vk_y) = get_coordinates(vk.0);
        let (r_x, r_y) = get_coordinates(r);
        let mut transcript = vec![DST_SCHNORR_SIGNATURE, vk_x, vk_y, r_x, r_y];
        transcript.extend_from_slice(msg);
        if PoseidonHash::hash(&transcript) != self.c {
            return Err(SignatureError::VerificationFailed);
        }
        Ok(())
    }
}
