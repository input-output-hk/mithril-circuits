//! Compact Schnorr signatures with a deterministic lottery projection.
//!
//! For secret scalar `x`, public key `vk = g * x`, and message hash point
//! `h = H1(msg)`, the tag is `sigma = h * x` (the paper calls this tag `u`).
//! A Chaum-Pedersen proof binds the tag and public key to the same secret.
//! `H1` is the Poseidon-based Jubjub hash-to-curve map; messages are ordered
//! slices of [`JubjubBase`] elements.
//!
//! Signing samples a nonce `r` and forms `R1 = h * r` and `R2 = g * r`. The
//! challenge transcript is the following ordered list of field elements:
//!
//! ```text
//! c = Poseidon(DST_UNIQUE_SIGNATURE,
//!              h_x, h_y, vk_x, vk_y, sigma_x, sigma_y,
//!              R1_x, R1_y, R2_x, R2_y)
//! ```
//!
//! Each point contributes its affine Edwards coordinates. The message enters
//! this transcript through `h`; the message fields and fixed generator `g`
//! are not separate transcript inputs, unlike in the paper's compact scheme.
//! The stored `c` is in [`JubjubBase`]. Its canonical integer is reduced modulo
//! the subgroup order to obtain `c_scalar`, and signing computes
//! `s = r - c_scalar * x`. Verification reconstructs
//! `R1 = h * s + sigma * c_scalar` and `R2 = g * s + vk * c_scalar`, then checks
//! the full base-field challenge. The paper instead stores a scalar challenge
//! and uses the opposite sign convention for the response and reconstruction.
//!
//! [`Signature`] stores `(sigma, s, c)`. [`LongSignature`] stores the commitments
//! explicitly and derives the challenge during verification. Fresh nonces change
//! either proof representation while leaving the tag for a fixed key/message
//! unchanged. This tag, exposed as affine coordinates by [`Signature::sigma`],
//! supplies the lottery projection; the complete signature is randomized.
//!
//! Native point types enforce prime-order subgroup membership. Unlike the
//! paper's nonzero-key requirement, [`SigningKey::generate`] samples the whole
//! scalar field, including zero, and verification does not reject identity keys.
//! The hash-to-curve call does not add a rejection step for the identity either.

use crate::{
    DST_UNIQUE_SIGNATURE, HashCPU, HashToCurveCPU, JubjubBase, JubjubHashToCurve, JubjubScalar,
    JubjubSubgroup, PoseidonHash,
    utils::{get_coordinates, jubjub_base_to_scalar},
};
use ff::Field;
use group::Group;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

/// Failure of compact Schnorr signature verification.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// The reconstructed verification transcript does not match the signature.
    #[error("Verification failed: Signature is invalid.")]
    VerificationFailed,
}

/// Secret Jubjub scalar used for signing.
#[derive(Debug, Clone)]
pub struct SigningKey(JubjubScalar);

impl SigningKey {
    /// Samples a signing scalar with the supplied cryptographic RNG.
    ///
    /// Sampling includes zero; this method does not enforce a nonidentity key.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let sk = JubjubScalar::random(rng);
        SigningKey(sk)
    }

    /// Signs the ordered message fields with a fresh randomized proof.
    ///
    /// The tag is deterministic for this key and message. The RNG supplies the
    /// proof nonce; it does not affect the lottery projection. The challenge
    /// transcript and scalar conversion are described in the module documentation.
    pub fn sign(&self, msg: &[JubjubBase], rng: &mut (impl RngCore + CryptoRng)) -> Signature {
        let g = JubjubSubgroup::generator();
        let vk = g * self.0;

        let hash = JubjubHashToCurve::hash_to_curve(msg);
        let sigma = hash * self.0;
        let r = JubjubScalar::random(rng);
        let cap_r_1 = hash * r;
        let cap_r_2 = g * r;

        let (hx, hy) = get_coordinates(hash);
        let (vk_x, vk_y) = get_coordinates(vk);
        let (sigma_x, sigma_y) = get_coordinates(sigma);
        let (cap_r_1_x, cap_r_1_y) = get_coordinates(cap_r_1);
        let (cap_r_2_x, cap_r_2_y) = get_coordinates(cap_r_2);

        let c = PoseidonHash::hash(&[
            DST_UNIQUE_SIGNATURE,
            hx,
            hy,
            vk_x,
            vk_y,
            sigma_x,
            sigma_y,
            cap_r_1_x,
            cap_r_1_y,
            cap_r_2_x,
            cap_r_2_y,
        ]);
        let c_scalar = jubjub_base_to_scalar(c);
        let s = r - self.0 * c_scalar;

        Signature { sigma, s, c }
    }

    /// Signs with explicit proof commitments instead of storing the challenge.
    pub fn sign_long(
        &self,
        msg: &[JubjubBase],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> LongSignature {
        let g = JubjubSubgroup::generator();
        let vk = g * self.0;

        let hash = JubjubHashToCurve::hash_to_curve(msg);
        let sigma = hash * self.0;
        let r = JubjubScalar::random(rng);
        let cap_r_1 = hash * r;
        let cap_r_2 = g * r;

        let (hx, hy) = get_coordinates(hash);
        let (vk_x, vk_y) = get_coordinates(vk);
        let (sigma_x, sigma_y) = get_coordinates(sigma);
        let (cap_r_1_x, cap_r_1_y) = get_coordinates(cap_r_1);
        let (cap_r_2_x, cap_r_2_y) = get_coordinates(cap_r_2);

        let c = PoseidonHash::hash(&[
            DST_UNIQUE_SIGNATURE,
            hx,
            hy,
            vk_x,
            vk_y,
            sigma_x,
            sigma_y,
            cap_r_1_x,
            cap_r_1_y,
            cap_r_2_x,
            cap_r_2_y,
        ]);
        let c_scalar = jubjub_base_to_scalar(c);
        let s = r - self.0 * c_scalar;

        LongSignature {
            sigma,
            cap_r_1,
            cap_r_2,
            s,
        }
    }
}

/// Public key `g * x` in the prime-order Jubjub subgroup.
///
/// The wrapper permits the identity element; signature verification does not
/// perform the paper's nonidentity-key check.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerificationKey(pub JubjubSubgroup);

impl From<&SigningKey> for VerificationKey {
    fn from(sk: &SigningKey) -> Self {
        let g = JubjubSubgroup::generator();
        let vk = g * sk.0;
        VerificationKey(vk)
    }
}

impl VerificationKey {
    /// Returns `(x, y)` coordinates in the order used by registry leaves.
    pub fn to_field(&self) -> [JubjubBase; 2] {
        let (x, y) = get_coordinates(self.0);
        [x, y]
    }
}

/// Compact Schnorr signature `(sigma, s, c)`.
///
/// Only `sigma` is deterministic for a fixed key and message. `c` is stored in
/// the base field, while `s` and the reduced challenge used in curve arithmetic
/// belong to the scalar field. Certificate circuits use this representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Deterministic message hash point multiplied by the signing scalar.
    pub sigma: JubjubSubgroup,
    /// Proof response, computed as `r - (c mod q) * x` for subgroup order `q`.
    pub s: JubjubScalar,
    /// Poseidon transcript challenge before reduction to the scalar field.
    pub c: JubjubBase,
}

impl Signature {
    /// Reconstructs both proof commitments and checks their transcript challenge.
    ///
    /// `msg` must contain the same fields, in the same order, as at signing.
    /// Curve arithmetic uses the reduced scalar challenge; transcript equality
    /// compares the full stored base-field value. Identity keys are not rejected.
    pub fn verify(&self, msg: &[JubjubBase], vk: &VerificationKey) -> Result<(), SignatureError> {
        let g = JubjubSubgroup::generator();
        let hash = JubjubHashToCurve::hash_to_curve(msg);
        let c_scalar = jubjub_base_to_scalar(self.c);

        let (hx, hy) = get_coordinates(hash);
        let (vk_x, vk_y) = get_coordinates(vk.0);
        let (sigma_x, sigma_y) = get_coordinates(self.sigma);
        let cap_r_1_prime = hash * self.s + self.sigma * c_scalar;
        let cap_r_2_prime = g * self.s + vk.0 * c_scalar;
        let (cap_r_1_x_prime, cap_r_1_y_prime) = get_coordinates(cap_r_1_prime);
        let (cap_r_2_x_prime, cap_r_2_y_prime) = get_coordinates(cap_r_2_prime);
        let c_prime = PoseidonHash::hash(&[
            DST_UNIQUE_SIGNATURE,
            hx,
            hy,
            vk_x,
            vk_y,
            sigma_x,
            sigma_y,
            cap_r_1_x_prime,
            cap_r_1_y_prime,
            cap_r_2_x_prime,
            cap_r_2_y_prime,
        ]);

        if c_prime != self.c {
            return Err(SignatureError::VerificationFailed);
        }

        Ok(())
    }

    /// Returns the deterministic tag coordinates used in lottery evaluation.
    pub fn sigma(&self) -> (JubjubBase, JubjubBase) {
        let (x, y) = get_coordinates(self.sigma);
        (x, y)
    }
}

/// Expanded signature `(sigma, R1, R2, s)` retaining both nonce commitments.
///
/// It uses the same transcript as [`Signature`], but derives the base-field
/// challenge from the supplied commitments instead of storing it. Its verifier
/// checks both commitment equations individually.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongSignature {
    /// Deterministic message-dependent tag, shared with the compact representation.
    pub sigma: JubjubSubgroup,
    /// Nonce commitment `H_1(msg) * r`.
    pub cap_r_1: JubjubSubgroup,
    /// Nonce commitment `g * r`.
    pub cap_r_2: JubjubSubgroup,
    /// Proof response, computed as `r - (c mod q) * x` for subgroup order `q`.
    pub s: JubjubScalar,
}

impl LongSignature {
    /// Recomputes the challenge and checks both supplied commitment equations.
    pub fn verify(&self, msg: &[JubjubBase], vk: &VerificationKey) -> Result<(), SignatureError> {
        let g = JubjubSubgroup::generator();
        let hash = JubjubHashToCurve::hash_to_curve(msg);
        let (hx, hy) = get_coordinates(hash);
        let (vk_x, vk_y) = get_coordinates(vk.0);
        let (sigma_x, sigma_y) = get_coordinates(self.sigma);
        let (cap_r_1_x, cap_r_1_y) = get_coordinates(self.cap_r_1);
        let (cap_r_2_x, cap_r_2_y) = get_coordinates(self.cap_r_2);

        let c_prime = PoseidonHash::hash(&[
            DST_UNIQUE_SIGNATURE,
            hx,
            hy,
            vk_x,
            vk_y,
            sigma_x,
            sigma_y,
            cap_r_1_x,
            cap_r_1_y,
            cap_r_2_x,
            cap_r_2_y,
        ]);
        let c = jubjub_base_to_scalar(c_prime);

        {
            let right = hash * self.s + self.sigma * c;
            if self.cap_r_1 != right {
                return Err(SignatureError::VerificationFailed);
            }
        }

        {
            let right = g * self.s + vk.0 * c;
            if self.cap_r_2 != right {
                return Err(SignatureError::VerificationFailed);
            }
        }

        Ok(())
    }

    /// Replaces the explicit commitments with their transcript challenge.
    ///
    /// `hash_msg` must be `H_1(msg)` for the original signed message, and `vk`
    /// must be the original verification key. This conversion does not verify
    /// the proof; use [`Signature::verify`] to check the resulting signature.
    pub fn to_short_signature(&self, hash_msg: &JubjubSubgroup, vk: &VerificationKey) -> Signature {
        let (hx, hy) = get_coordinates(*hash_msg);
        let (vk_x, vk_y) = get_coordinates(vk.0);
        let (sigma_x, sigma_y) = get_coordinates(self.sigma);
        let (cap_r_1_x, cap_r_1_y) = get_coordinates(self.cap_r_1);
        let (cap_r_2_x, cap_r_2_y) = get_coordinates(self.cap_r_2);

        let c = PoseidonHash::hash(&[
            DST_UNIQUE_SIGNATURE,
            hx,
            hy,
            vk_x,
            vk_y,
            sigma_x,
            sigma_y,
            cap_r_1_x,
            cap_r_1_y,
            cap_r_2_x,
            cap_r_2_y,
        ]);

        Signature {
            sigma: self.sigma,
            s: self.s,
            c,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Test signing functionality.
    #[test]
    fn test_signature_unique_verification_valid() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let msg = JubjubBase::random(&mut rng);

        // Sign the message
        let signature = sk.sign(&[msg], &mut rng);

        // Ensure the components of the signature are non-default values
        assert_ne!(
            signature.sigma,
            JubjubSubgroup::identity(),
            "Signature sigma should not be the identity element."
        );
        assert_ne!(
            signature.s,
            JubjubScalar::ZERO,
            "Signature s component should not be zero."
        );
        assert_ne!(
            signature.c,
            JubjubBase::ZERO,
            "Signature c component should not be zero."
        );

        signature
            .verify(&[msg], &VerificationKey::from(&sk))
            .unwrap();
    }

    #[test]
    fn test_signature_unique_verification_invalid_signature() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let msg = JubjubBase::random(&mut rng);
        let vk: VerificationKey = (&sk).into();

        // Generate a signature and tamper with it.
        let mut signature = sk.sign(&[msg], &mut rng);
        signature.s = JubjubScalar::random(&mut rng); // Modify the `s` component.

        // Verify the modified signature.
        let result = signature.verify(&[msg], &vk);
        assert!(
            result.is_err(),
            "Invalid signature should fail verification, but it passed."
        );
    }

    #[test]
    fn test_signature_unique_long_verification_valid() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk: VerificationKey = (&sk).into();
        let msg = JubjubBase::random(&mut rng);

        // Generate an expanded signature.
        let sig_long = sk.sign_long(&[msg], &mut rng);
        // Verify the expanded signature.
        assert!(sig_long.verify(&[msg], &vk).is_ok());

        let hash_msg = JubjubHashToCurve::hash_to_curve(&[msg]);
        let sig = sig_long.to_short_signature(&hash_msg, &vk);
        assert!(sig.verify(&[msg], &vk).is_ok());
    }
}
