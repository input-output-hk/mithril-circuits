//! Registration-time targets and native lottery checks.
//!
//! A signer is eligible when the Poseidon evaluation of the lottery context,
//! deterministic signature tag, and index is at most its registered target.
//! The tag is the `sigma` point of a compact Schnorr signature; its randomized
//! proof components do not enter the lottery evaluation.
//! Floating-point work happens in [`target`]; certificate circuits use the
//! committed field target and the same inclusive comparison.

use crate::{DST_LOTTERY, HashCPU, JubjubBase, PoseidonHash, Target, schnorr_signature::Signature};
use ff::Field;
use rug::{Float, Integer, float::Round, integer::Order, ops::Pow};
use std::cmp::Ordering;
use thiserror::Error;

type Stake = u64;
type F = JubjubBase;

/// Failure of a native lottery index or eligibility check.
#[derive(Debug, Error)]
pub enum LotteryError {
    /// The index is outside the lottery range or its evaluation exceeds the target.
    #[error("Verification failed: Index is invalid.")]
    VerificationFailed,
}

/// Computes the inclusive eligibility target to commit at registration.
///
/// The probability estimate is `1 - (1 - phi_f)^(stake / total_stake)`.
/// It is scaled by the field modulus to produce a target for the native lottery
/// check.
///
/// # Panics
///
/// Panics if `phi_f` is outside `[0, 1]` (including NaN), or if the computed
/// value cannot be converted to the expected nonnegative field target.
pub fn target(phi_f: f64, stake: Stake, total_stake: Stake) -> Target {
    // modulus - 1
    let ev_max = -F::ONE;

    assert!(phi_f <= 1.0, "phi_f must be less than or equal to 1.0");
    assert!(0.0 <= phi_f, "phi_f must be greater than or equal to 0.0");

    // Match the prototype's near-one convention before computing stake weighting.
    if (phi_f - 1.0).abs() < f64::EPSILON {
        return ev_max;
    }

    // JubjubBase modulus
    let modulus = Integer::from_str_radix(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        16,
    )
    .unwrap();

    let w = Float::with_val(117, stake) / Float::with_val(117, total_stake);
    let phi = Float::with_val(117, 1.0) - Float::with_val(117, 1.0 - phi_f).pow(w);
    // Use higher working precision for scaling this estimate by the modulus.
    let phi_high = Float::with_val(300, phi);

    let t = modulus * phi_high;
    let (t_int, order) = t.to_integer_round(Round::Zero).unwrap();
    assert!(t_int >= 0);

    let target = match order {
        Ordering::Less => t_int,
        Ordering::Equal => {
            if t_int == 0 {
                // Hashing to zero has negligible probability.
                t_int
            } else {
                t_int - 1
            }
        }
        Ordering::Greater => unreachable!(),
    };

    let mut bytes: Vec<u8> = target.to_digits(Order::LsfLe);
    bytes.resize(32, 0);

    F::from_bytes_le(&bytes.try_into().unwrap()).unwrap()
}

/// Hashes `DST_LOTTERY || msg` into the prefix shared by a context's lotteries.
///
/// Certificate circuits use `[merkle_root, topic]` as the message context.
pub fn lottery_prefix(msg: &[JubjubBase]) -> JubjubBase {
    let mut prefix = vec![DST_LOTTERY];
    prefix.extend_from_slice(msg);

    PoseidonHash::hash(&prefix)
}

/// Checks `index < m` and the inclusive lottery bound for a signature tag.
///
/// The evaluation is `Poseidon(prefix, sigma_x, sigma_y, index)`, using the
/// deterministic point in the signature. Signature validity and registry
/// membership are separate checks performed by callers or the certificate
/// circuit; this function only evaluates lottery eligibility.
pub fn check_index(
    sig: &Signature,
    index: u32,
    m: u32,
    prefix: JubjubBase,
    target: Target,
) -> Result<(), LotteryError> {
    if index >= m {
        return Err(LotteryError::VerificationFailed);
    }

    let idx = F::from(index as u64);
    let (sigma_x, sigma_y) = sig.sigma();
    let ev = PoseidonHash::hash(&[prefix, sigma_x, sigma_y, idx]);

    // Check whether ev <= target.
    if ev > target {
        return Err(LotteryError::VerificationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr_signature::SigningKey;
    use rand_core::OsRng; // Import all elements from the module

    #[test]
    fn test_target_phi_f_one() {
        // Case where `phi_f` is exactly 1
        let phi_f = 1.0;
        let stake = 50;
        let total_stake = 100;

        let result = target(phi_f, stake, total_stake);

        // Since `phi_f` is 1, the function should return the maximum target (-F::ONE)
        assert_eq!(result, -F::ONE);
    }

    #[test]
    fn test_target_half_stake() {
        // Case where `stake` is exactly half of `total_stake`
        let phi_f = 0.5;
        let stake = 50;
        let total_stake = 100;

        let result = target(phi_f, stake, total_stake);

        // Validate that result is in the expected range
        assert!(result != -F::ONE);
    }

    #[test]
    fn test_check_index() {
        let phi_f = 0.2;
        let stake = 30;
        let total_stake = 100;

        let target = target(phi_f, stake, total_stake);
        println!("Target = {:?}", target);

        let sk = SigningKey::generate(&mut OsRng);
        let msg = JubjubBase::random(&mut OsRng);
        let sig = sk.sign(&[msg], &mut OsRng);

        let m = 100;
        let mut counter = 0;
        let prefix = lottery_prefix(&[msg]);
        for i in 0..m {
            if check_index(&sig, i, m, prefix, target).is_ok() {
                println!("Index: {}", i);
                counter += 1;
            }
        }
        println!("Total eligible indices:{:?}", counter);
    }
}
