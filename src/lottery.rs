use crate::{HashCPU, JubjubBase, Msg, PoseidonHash, Signature, Target};
use ff::Field;
use rug::{Float, Integer, float::Round, integer::Order, ops::Pow};
use std::cmp::Ordering;
use thiserror::Error;

type Stake = u64;
type F = JubjubBase;

#[derive(Debug, Error)]
pub enum LotteryError {
    #[error("Verification failed: Index is invalid.")]
    VerificationFailed,
    /// This error occurs when the serialization of the raw bytes failed
    #[error("Invalid bytes")]
    SerializationError,
}

pub fn target(phi_f: f64, stake: Stake, total_stake: Stake) -> Target {
    // modulus - 1
    let ev_max = -F::ONE;

    assert!(phi_f <= 1.0, "phi_f must be less than or equal to 1.0");
    assert!(0.0 <= phi_f, "phi_f must be greater than or equal to 0.0");

    // If phi_f = 1, then we automatically break with true
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
    // increase precision
    let phi_high = Float::with_val(300, phi);

    let t = modulus * phi_high;
    let (t_int, order) = t.to_integer_round(Round::Zero).unwrap();
    assert!(t_int >= 0);

    let target = match order {
        Ordering::Less => t_int,
        Ordering::Equal => {
            if t_int == 0 {
                // hashing to 0 has negligible probability
                t_int
            } else {
                t_int - 1
            }
        }
        Ordering::Greater => unreachable!(),
    };

    let mut bytes: Vec<u8> = target.to_digits(Order::LsfLe);
    bytes.resize(32, 0);
    let target = F::from_bytes_le(&bytes.try_into().unwrap()).unwrap();
    target
}

pub fn check_index(
    sig: &Signature,
    index: u32,
    m: u32,
    msg: Msg,
    target: Target,
) -> Result<(), LotteryError> {
    if index > m {
        return Err(LotteryError::VerificationFailed);
    }

    let idx = F::from(index as u64);
    let (sigma_x, sigma_y) = sig.sigma();
    let ev = PoseidonHash::hash(&[msg, sigma_x, sigma_y, idx]);

    // check if ev <= target
    if ev > target {
        return Err(LotteryError::VerificationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKey;
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
        let msg = Msg::random(&mut OsRng);
        let sig = sk.sign(msg, &mut OsRng);

        let m = 100;
        let mut counter = 0;
        for i in 0..m {
            if check_index(&sig, i, m, msg, target).is_ok() {
                println!("Index: {}", i);
                counter += 1;
            }
        }
        println!("Total eligible indices:{:?}", counter);
    }
}
