use crate::{JubjubAffine, JubjubBase, JubjubExtended, JubjubScalar, JubjubSubgroup};
use blstrs::EDWARDS_D;
use ff::{Field, PrimeField, PrimeFieldBits};
use subtle::{Choice, ConstantTimeEq};

pub fn get_coordinates(point: JubjubSubgroup) -> (JubjubBase, JubjubBase) {
    let extended: JubjubExtended = point.into(); // Convert to JubjubExtended
    let affine: JubjubAffine = extended.into(); // Convert to JubjubAffine (affine coordinates)
    let x = affine.get_u(); // Get x-coordinate
    let y = affine.get_v(); // Get y-coordinate
    (x, y)
}

pub fn jubjub_base_to_scalar(x: JubjubBase) -> JubjubScalar {
    let bytes = x.to_bytes_le();
    JubjubScalar::from_raw([
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ])
}

pub fn is_on_curve(u: JubjubBase, v: JubjubBase) -> Choice {
    let u2 = u.square();
    let v2 = v.square();

    // Left-hand side: v² - u²
    let lhs = v2 - u2;

    // Right-hand side: 1 + EDWARDS_D * (u² * v²)
    let rhs = JubjubBase::ONE + EDWARDS_D * u2 * v2;

    // Compare in constant time
    lhs.ct_eq(&rhs)
}

// decompose a JubjubBase into three 85-bit JubjubBase elements
pub fn decompose(value: &JubjubBase) -> Vec<JubjubBase> {
    // Convert the field element to little-endian bits
    let bits = value.to_le_bits();

    // Split the 255-bit representation into three 85-bit segments
    let b1_bits = &bits[0..85];
    let b2_bits = &bits[85..170];
    let b3_bits = &bits[170..255];

    // Convert the bit slices to u128 values
    let b1_value = u128::from_le_bytes({
        let mut buffer = [0u8; 16]; // 128 bits
        for (i, bit) in b1_bits.iter().enumerate() {
            if *bit {
                buffer[i / 8] |= 1 << (i % 8);
            }
        }
        buffer
    });

    let b2_value = u128::from_le_bytes({
        let mut buffer = [0u8; 16]; // 128 bits
        for (i, bit) in b2_bits.iter().enumerate() {
            if *bit {
                buffer[i / 8] |= 1 << (i % 8);
            }
        }
        buffer
    });

    let b3_value = u128::from_le_bytes({
        let mut buffer = [0u8; 16]; // 128 bits
        for (i, bit) in b3_bits.iter().enumerate() {
            if *bit {
                buffer[i / 8] |= 1 << (i % 8);
            }
        }
        buffer
    });

    // Convert the u128 values into `JubjubBase` elements
    let limb1 = JubjubBase::from_u128(b1_value);
    let limb2 = JubjubBase::from_u128(b2_value);
    let limb3 = JubjubBase::from_u128(b3_value);

    let base_85 = JubjubBase::from_u128(1_u128 << 85);
    let base_170 = base_85 * base_85;
    // Reconstruct the original value
    let res = limb1 + limb2 * base_85 + limb3 * base_170;
    res.ct_eq(&value);

    vec![limb1, limb2, limb3]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_decompose() {
        let ran = JubjubBase::random(&mut OsRng);
        let decomposed = decompose(&ran);

        assert_eq!(decomposed.len(), 3);
    }
}
