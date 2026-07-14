use crate::{DST_LOTTERY, HashCPU, JubjubBase, PoseidonHash, Target, unique_signature::Signature};
use dashu::{
    base::{BitTest, DivRem},
    float::{FBig, round::mode::HalfEven},
    integer::UBig,
};
use ff::Field;
use thiserror::Error;

/// Binary arbitrary-precision float rounding to nearest (ties to even), like MPFR's default.
type BigFloat = FBig<HalfEven, 2>;

/// A positive dyadic rational `significand * 2^exponent`.
type Dyadic = (UBig, i64);

/// Round the dyadic value `sig * 2^exp` to `prec` significant bits (nearest, ties
/// to even), replicating MPFR's per-operation rounding. `sticky` marks a value
/// that is strictly greater than `sig * 2^exp` by less than one unit in the last
/// place of `sig` (a truncated quotient); it breaks would-be ties upward.
fn round_dyadic(sig: UBig, exp: i64, prec: usize, sticky: bool) -> Dyadic {
    let bits = sig.bit_len();
    if bits <= prec {
        debug_assert!(!sticky, "sticky rounding requires at least prec + 1 bits");
        return (sig, exp);
    }
    let shift = bits - prec;
    let half = UBig::ONE << (shift - 1);
    let low = sig.clone() & ((UBig::ONE << shift) - UBig::ONE);
    let mut top = sig >> shift;
    let round_up = match low.cmp(&half) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Equal => sticky || top.bit(0),
        std::cmp::Ordering::Less => false,
    };
    if round_up {
        top += UBig::ONE;
    }
    (top, exp + shift as i64)
}

/// Round the rational `num / den` to `prec` significant bits, nearest, ties to even.
fn round_ratio(num: &UBig, den: &UBig, prec: usize) -> Dyadic {
    if num == &UBig::ZERO {
        return (UBig::ZERO, 0);
    }
    // Scale so the truncated quotient carries at least prec + 2 bits, then round
    // with the remainder as the sticky bit.
    let mut s = (prec as i64 + 2 + den.bit_len() as i64 - num.bit_len() as i64).max(0) as usize;
    loop {
        let (q, r) = (num << s).div_rem(den);
        if q.bit_len() >= prec + 2 {
            return round_dyadic(q, -(s as i64), prec, r != UBig::ZERO);
        }
        s += 1;
    }
}

/// The exact dyadic value of a non-negative, finite `f64`.
fn dyadic_from_f64(x: f64) -> Dyadic {
    let f = BigFloat::try_from(x).unwrap();
    let (sig, exp) = f.into_repr().into_parts();
    (sig.try_into().unwrap(), exp as i64)
}

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
    let modulus = UBig::from_str_radix(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        16,
    )
    .unwrap();

    // All roundings below are done in exact integer arithmetic (round_*), not by
    // dashu, whose operations do not reliably round to the operand precision the
    // way MPFR does (they may keep extra exact bits, causing double rounding).
    // dashu is only used for the transcendental step, `powf`.
    let w = round_ratio(&UBig::from(stake), &UBig::from(total_stake), 117);
    // exact: an f64 has at most 53 significant bits
    let base = dyadic_from_f64(1.0 - phi_f);

    // pow = round117(base^w). powf is evaluated with 200-bit precision and rounded
    // down to 117 bits; the double rounding differs from MPFR's correctly-rounded
    // pow only if base^w lies within ~2^-195 of a 117-bit rounding boundary.
    let pow: Dyadic = {
        let base_f = BigFloat::from_parts(base.0.into(), base.1 as isize)
            .with_precision(200)
            .value();
        let w_f = BigFloat::from_parts(w.0.into(), w.1 as isize)
            .with_precision(200)
            .value();
        let (sig, exp) = base_f.powf(&w_f).into_repr().into_parts();
        round_dyadic(sig.try_into().unwrap(), exp as i64, 117, false)
    };

    // phi = round117(1 - pow), computed exactly: pow <= 1 and 1 - s*2^e = (2^-e - s)*2^e
    let (pow_sig, pow_exp) = pow;
    debug_assert!(pow_exp <= 0);
    let phi_sig = (UBig::ONE << (-pow_exp) as usize) - pow_sig;
    let (phi_sig, phi_exp) = round_dyadic(phi_sig, pow_exp, 117, false);

    // t = round300(modulus * phi), then truncate toward zero; `exact` marks an
    // integer-valued t (rug's Ordering::Equal case)
    let (t_sig, t_exp) = round_dyadic(modulus * phi_sig, phi_exp, 300, false);
    let (t_int, exact) = if t_exp >= 0 {
        (t_sig << t_exp as usize, true)
    } else {
        let sh = (-t_exp) as usize;
        let int = t_sig.clone() >> sh;
        let exact = (int.clone() << sh) == t_sig;
        (int, exact)
    };

    let target = if !exact || t_int == UBig::ZERO {
        // hashing to 0 has negligible probability
        t_int
    } else {
        t_int - UBig::ONE
    };

    let mut bytes: Vec<u8> = target.to_le_bytes().to_vec();
    bytes.resize(32, 0);
    let target = F::from_bytes_le(&bytes.try_into().unwrap()).unwrap();
    target
}

pub fn lottery_prefix(msg: &[JubjubBase]) -> JubjubBase {
    let mut prefix = vec![DST_LOTTERY];
    prefix.extend_from_slice(msg);
    let prefix_hash = PoseidonHash::hash(&prefix);
    prefix_hash
}

pub fn check_index(
    sig: &Signature,
    index: u32,
    m: u32,
    prefix: JubjubBase,
    target: Target,
) -> Result<(), LotteryError> {
    if index > m {
        return Err(LotteryError::VerificationFailed);
    }

    let idx = F::from(index as u64);
    let (sigma_x, sigma_y) = sig.sigma();
    let ev = PoseidonHash::hash(&[prefix, sigma_x, sigma_y, idx]);

    // check if ev <= target
    if ev > target {
        return Err(LotteryError::VerificationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unique_signature::SigningKey;
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
        let phi_f = 0.05;
        let stake = 1;
        let total_stake = 45_000_000_000;

        let result = target(phi_f, stake, total_stake);
        println!("Result: {:?} for stake {:?}", result, stake);

        // Validate that result is in the expected range
        assert!(result != -F::ONE);
    }

    /// Reference targets computed by the original rug/MPFR implementation.
    /// The dashu-based implementation must reproduce them bit-for-bit: the
    /// target is committed in the Merkle leaf, so it is consensus-critical.
    /// Includes the cases where naive dashu usage diverged from MPFR by 1 ulp
    /// (double rounding in `1 - pow` and in `powf` itself).
    #[test]
    fn test_target_mpfr_reference_vectors() {
        let vectors: [(f64, u64, u64, &str); 8] = [
            (
                0.05,
                1,
                45_000_000_000,
                "0000000000914a646e9cd7b696967c1f05f5ac4531f951b74d0383f6c4aec15f",
            ),
            (
                0.2,
                30,
                100,
                "0781ac943416ead52986bf8aa2bf63b288a8433f3f1b2eb0916fdd486370ee94",
            ),
            (
                0.75,
                44_999_999_999,
                45_000_000_000,
                "56f23d7e5b606e797ea267626dd5015bef72b1e1810866313b55f95d747ec61b",
            ),
            (
                0.9,
                50,
                100,
                "4f44c1691cd4033f8c47c1ec370dc2938ea46f87b26fb4ed96d757403203098f",
            ),
            (
                0.9,
                44_999_999_999,
                45_000_000_000,
                "6855e3646fb4b9bd9657778ad11980cbde44a72c1f346e7ba23229b421e3be89",
            ),
            (
                0.99,
                44_999_999_999,
                45_000_000_000,
                "72c4e08816c4fd644ee0bdb20c47d2af41547c6eede16ebb14d750dea1a960c5",
            ),
            (
                0.999999,
                50,
                100,
                "73cff9d874930d1d623c3a4cf41b78bb98f3c5b4796237037a3d419f85988f0a",
            ),
            (
                0.999999,
                99,
                100,
                "73ed9e9a0e46d9f9c8f2ff229207058cb5fbf1cf08e9b0718860e9e7367c1f87",
            ),
        ];
        for (phi_f, stake, total, expected_be_hex) in vectors {
            let mut bytes: [u8; 32] = hex_to_bytes(expected_be_hex);
            bytes.reverse(); // big-endian hex -> little-endian bytes
            let expected = F::from_bytes_le(&bytes).unwrap();
            assert_eq!(
                target(phi_f, stake, total),
                expected,
                "target({phi_f}, {stake}, {total})"
            );
        }
    }

    fn hex_to_bytes(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
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
