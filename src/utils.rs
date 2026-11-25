//! Field encodings and integer decompositions for native and witness calculations.
//!
//! These helpers run on the host. Circuit callers must separately constrain
//! any assigned values derived from their results.

use crate::{Jubjub, JubjubAffine, JubjubBase, JubjubScalar, JubjubSubgroup};
use ff::PrimeField;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{Num, One, Zero};

/// Returns the affine Edwards `(x, y)` coordinates of a subgroup point.
pub fn get_coordinates(point: JubjubSubgroup) -> (JubjubBase, JubjubBase) {
    let extended: Jubjub = point.into(); // Convert to JubjubExtended
    let affine: JubjubAffine = extended.into(); // Convert to JubjubAffine (affine coordinates)
    let x = affine.get_u(); // Get x-coordinate
    let y = affine.get_v(); // Get y-coordinate
    (x, y)
}

/// Reduces a base-field element's canonical integer modulo the scalar modulus.
///
/// Native signature verification uses this to interpret a Poseidon challenge
/// as a scalar for curve multiplication.
pub fn jubjub_base_to_scalar(x: JubjubBase) -> JubjubScalar {
    let bytes = x.to_bytes_le();
    JubjubScalar::from_raw([
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ])
}

/// Interprets 32 little-endian bytes as an integer and reduces it modulo the field.
///
/// This is a reducing conversion, not a canonical-encoding check. Use
/// [`JubjubBase::from_bytes_le`] when noncanonical encodings must be rejected.
///
/// # Panics
///
/// Panics if the input is not exactly 32 bytes.
pub fn jubjub_base_from_le_bytes(bytes: &[u8]) -> JubjubBase {
    assert_eq!(bytes.len(), 32);
    JubjubBase::from_raw([
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ])
}

/// Decomposes an integer into exactly `nb_limbs` digits in little-endian order.
///
/// # Panics
///
/// Panics if `base` is zero or the value does not fit in the requested limbs.
pub fn big_to_limbs(nb_limbs: u32, base: &BigUint, value: &BigUint) -> Vec<BigUint> {
    let mut output = vec![];
    let mut q = (*value).clone();
    let mut r;
    while output.len() < nb_limbs as usize {
        (q, r) = q.div_rem(base);
        output.push(r.clone());
    }
    if !BigUint::is_zero(&q) {
        panic!(
            "big_to_limbs: {} cannot be expressed in base {} with {} limbs",
            value, base, nb_limbs
        )
    };
    output
}

/// Reads a prime field's modulus from its `0x`-prefixed hexadecimal constant.
pub fn modulus<F: PrimeField>() -> BigUint {
    BigUint::from_str_radix(&F::MODULUS[2..], 16).unwrap()
}

/// Reduces a nonnegative integer modulo the field modulus before conversion.
pub fn big_to_fe<F: PrimeField>(e: BigUint) -> F {
    let modulus = modulus::<F>();
    let e = e % modulus;
    F::from_str_vartime(&e.to_str_radix(10)[..]).unwrap()
}

/// Splits a canonical field representative into little-endian fixed-width limbs.
///
/// The vector contains only the required limbs; zero yields an empty vector.
///
/// # Panics
///
/// Panics if `limb_bits` is zero.
pub fn decompose<F: PrimeField>(value: &F, limb_bits: usize) -> Vec<F> {
    let value_big = BigUint::from_bytes_le(value.to_repr().as_ref());
    let nb_limbs = value_big.bits().div_ceil(limb_bits as u64) as u32;
    big_to_limbs(nb_limbs, &(BigUint::from(1u8) << limb_bits), &value_big)
        .into_iter()
        .map(big_to_fe::<F>)
        .collect()
}

/// Returns low and high parts of a field element's canonical integer.
///
/// The low part contains `num_bits` bits and the high part is the remaining
/// quotient, so `value = low + 2^num_bits * high` as integers.
pub fn split<F: PrimeField>(value: &F, num_bits: u32) -> (F, F) {
    let value_big = BigUint::from_bytes_le(value.to_repr().as_ref());
    let lower_mask = (BigUint::one() << num_bits) - BigUint::one(); // Create a mask for n bits
    let lower_big = value_big.clone() & &lower_mask;
    let upper_big = value_big >> num_bits;
    let lower = big_to_fe::<F>(lower_big);
    let upper = big_to_fe::<F>(upper_big);
    (lower, upper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand_core::OsRng;
    use subtle::ConstantTimeEq;

    #[test]
    fn test_decompose() {
        let ran = JubjubBase::random(&mut OsRng);
        let limb_bits = 85;
        let limbs = decompose(&ran, limb_bits);
        assert_eq!(limbs.len(), 3);

        let mut reconstructed = JubjubBase::ZERO;
        let base = JubjubBase::from_u128(1_u128 << limb_bits);
        for (i, limb) in limbs.iter().enumerate() {
            reconstructed += base.pow_vartime([i as u64]) * limb;
        }
        assert_eq!(
            reconstructed.ct_eq(&ran).unwrap_u8(),
            1,
            "Decomposition failed!"
        );
    }

    #[test]
    fn test_split() {
        let ran = JubjubBase::random(&mut OsRng);
        let num_bits = 120;
        let (lower, upper) = split(&ran, num_bits);

        let base = JubjubBase::from_u128(1_u128 << num_bits);
        let reconstructed = lower + base * upper;
        assert_eq!(
            reconstructed.ct_eq(&ran).unwrap_u8(),
            1,
            "Splitting failed!"
        );
    }

    #[test]
    fn test_bytes() {
        let ran = JubjubBase::random(&mut OsRng);
        let bytes = ran.to_bytes_le();

        let base = jubjub_base_from_le_bytes(&bytes);
        assert_eq!(ran, base);
    }
}
