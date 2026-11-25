//! Certificate relations and their shared verification gadgets.
//!
//! [`certificate_topiconly`] verifies one signature per winning index.
//! [`certificate_topicbody`] verifies a topic signature for eligibility and a
//! second signature binding the topic and body. Both authenticate registered
//! keys and targets with Poseidon Merkle paths and enforce ordered indices.
//! Both use compact [`crate::schnorr_signature::Signature`] witnesses.

use crate::{
    ArithInstructions, AssertionInstructions, AssignedBit, AssignedNative, AssignedNativePoint,
    AssignedScalarOfNativeCurve, AssignmentInstructions, BinaryInstructions,
    ControlFlowInstructions, DecompositionInstructions, EccInstructions, EqualityInstructions,
    Error, Jubjub, JubjubBase, Layouter, ZkStdLib, utils::split,
};
use ff::{Field, PrimeField};

pub mod certificate_topicbody;
pub mod certificate_topiconly;

#[cfg(test)]
mod test_srs;

type F = JubjubBase;
type C = Jubjub;

/// Constrains the canonical integer representatives to have the same low bit.
fn assert_equal_parity(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    x: &AssignedNative<F>,
    y: &AssignedNative<F>,
) -> Result<(), Error> {
    let sgn0 = std_lib.sgn0(layouter, x)?;
    let sgn1 = std_lib.sgn0(layouter, y)?;
    std_lib.assert_equal(layouter, &sgn0, &sgn1)
}

/// Assigns a low/high split, constraining recomposition modulo the field and parity.
///
/// This helper alone does not bound the limbs. Callers must enforce a 127-bit
/// low limb and a 128-bit high limb. With those bounds, the parity check rules
/// out the alternative representation obtained by adding the odd modulus.
fn decompose_unsafe(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    x: &AssignedNative<F>,
) -> Result<(AssignedNative<F>, AssignedNative<F>), Error> {
    // Decompose the 255-bit value into 127-bit and 128-bit values.
    let x_value = x.value();
    let base127 = F::from_u128(1_u128 << 127);
    let (x_low, x_high) = x_value.map(|v| split(v, 127)).unzip();

    let x_low_assigned: AssignedNative<_> = std_lib.assign(layouter, x_low)?;
    let x_high_assigned: AssignedNative<_> = std_lib.assign(layouter, x_high)?;

    let x_combined: AssignedNative<_> = std_lib.linear_combination(
        layouter,
        &[
            (F::ONE, x_low_assigned.clone()),
            (base127, x_high_assigned.clone()),
        ],
        F::ZERO,
    )?;
    std_lib.assert_equal(layouter, x, &x_combined)?;

    // Verify that the least significant bit is consistent to ensure a unique decomposition.
    // This works because the modulus is odd.
    assert_equal_parity(std_lib, layouter, x, &x_low_assigned)?;

    Ok((x_low_assigned, x_high_assigned))
}

/// Compares canonical field representatives through bounded low/high limbs.
///
/// The standard library comparisons range-check both operands of each limb
/// comparison, completing the bounds required by `decompose_unsafe`.
fn lower_than_native(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    x: &AssignedNative<F>,
    y: &AssignedNative<F>,
) -> Result<AssignedBit<F>, Error> {
    let (x_low_assigned, x_high_assigned) = decompose_unsafe(std_lib, layouter, x)?;
    let (y_low_assigned, y_high_assigned) = decompose_unsafe(std_lib, layouter, y)?;

    // Check whether x < y.
    let is_equal_high = std_lib.is_equal(layouter, &x_high_assigned, &y_high_assigned)?;
    let is_less_low = std_lib.lower_than(layouter, &x_low_assigned, &y_low_assigned, 127)?;
    let is_less_high = std_lib.lower_than(layouter, &x_high_assigned, &y_high_assigned, 128)?;

    let low_less = std_lib.and(layouter, &[is_equal_high, is_less_low])?;
    std_lib.or(layouter, &[is_less_high, low_less])
}

/// Authenticates `Poseidon(vk_x, vk_y, target)` against the public registry root.
///
/// Position zero places the sibling on the left; one places it on the right.
fn verify_merkle_path(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    vk: &AssignedNativePoint<C>,
    target: &AssignedNative<F>,
    merkle_root: &AssignedNative<F>,
    merkle_siblings: &[AssignedNative<F>],
    merkle_positions: &[AssignedBit<F>],
) -> Result<(), Error> {
    let vk_x = std_lib.jubjub().x_coordinate(vk);
    let vk_y = std_lib.jubjub().y_coordinate(vk);
    let leaf = std_lib.poseidon(layouter, &[vk_x.clone(), vk_y.clone(), target.clone()])?;
    let root = merkle_siblings
        .iter()
        .zip(merkle_positions.iter())
        .try_fold(leaf, |acc, (x, pos)| {
            // Choose the left child for hashing:
            // If pos is 1 (sibling on the right), choose the current node; otherwise, the sibling.
            let left = std_lib.select(layouter, pos, &acc, x)?;

            // Choose the right child for hashing:
            // If pos is 1 (sibling on the right), choose the sibling; otherwise, the current node.
            let right = std_lib.select(layouter, pos, x, &acc)?;

            std_lib.poseidon(layouter, &[left, right])
        })?;

    std_lib.assert_equal(layouter, &root, merkle_root)
}

/// References to a compact Schnorr tag, response, and two forms of the challenge.
///
/// `c_native` is compared with the Poseidon challenge; `c` is its scalar form
/// used in the two elliptic-curve verification equations.
struct AssignedUniqueSignature<'a> {
    sigma: &'a AssignedNativePoint<C>,
    s: &'a AssignedScalarOfNativeCurve<C>,
    c: &'a AssignedScalarOfNativeCurve<C>,
    c_native: &'a AssignedNative<F>,
}

/// Checks a compact Schnorr signature using a precomputed message hash point.
///
/// Reconstructs `R1 = hash * s + sigma * c` and `R2 = generator * s + vk * c`,
/// where `c` is the scalar form of the challenge. Hashes the domain tag followed
/// by the affine coordinates of `(hash, vk, sigma, R1, R2)` and compares the full
/// base-field result with `c_native`. The message is bound through `hash`; the
/// generator and raw message fields are not separate transcript inputs.
fn verify_unique_signature(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    dst_signature: &AssignedNative<F>,
    generator: &AssignedNativePoint<C>,
    vk: &AssignedNativePoint<C>,
    hash: &AssignedNativePoint<C>,
    signature: AssignedUniqueSignature<'_>,
) -> Result<(), Error> {
    let AssignedUniqueSignature {
        sigma,
        s,
        c,
        c_native,
    } = signature;

    // Compute R1
    let cap_r_1 = std_lib.jubjub().msm(
        layouter,
        &[s.clone(), c.clone()],
        &[hash.clone(), sigma.clone()],
    )?;

    // Compute R2
    let cap_r_2 = std_lib.jubjub().msm(
        layouter,
        &[s.clone(), c.clone()],
        &[generator.clone(), vk.clone()],
    )?;

    // Hash the domain tag and affine coordinates of (H1(msg), vk, sigma, R1, R2).
    let hx = std_lib.jubjub().x_coordinate(hash);
    let hy = std_lib.jubjub().y_coordinate(hash);
    let vk_x = std_lib.jubjub().x_coordinate(vk);
    let vk_y = std_lib.jubjub().y_coordinate(vk);
    let sigma_x = std_lib.jubjub().x_coordinate(sigma);
    let sigma_y = std_lib.jubjub().y_coordinate(sigma);
    let cap_r_1_x = std_lib.jubjub().x_coordinate(&cap_r_1);
    let cap_r_1_y = std_lib.jubjub().y_coordinate(&cap_r_1);
    let cap_r_2_x = std_lib.jubjub().x_coordinate(&cap_r_2);
    let cap_r_2_y = std_lib.jubjub().y_coordinate(&cap_r_2);

    let c_prime = std_lib.poseidon(
        layouter,
        &[
            dst_signature.clone(),
            hx,
            hy,
            vk_x,
            vk_y,
            sigma_x.clone(),
            sigma_y.clone(),
            cap_r_1_x,
            cap_r_1_y,
            cap_r_2_x,
            cap_r_2_y,
        ],
    )?;
    std_lib.assert_equal(layouter, c_native, &c_prime)
}

/// Checks `Poseidon(prefix, sigma_x, sigma_y, index) <= target` in the circuit.
///
/// Index bounds, signature validity, and target authentication are enforced by
/// the surrounding certificate relation.
fn verify_lottery(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    lottery_prefix: &AssignedNative<F>,
    sigma: &AssignedNativePoint<C>,
    index: &AssignedNative<F>,
    target: &AssignedNative<F>,
) -> Result<(), Error> {
    let sigma_x = std_lib.jubjub().x_coordinate(sigma);
    let sigma_y = std_lib.jubjub().y_coordinate(sigma);
    let ev = std_lib.poseidon(
        layouter,
        &[lottery_prefix.clone(), sigma_x, sigma_y, index.clone()],
    )?;
    let is_less = lower_than_native(std_lib, layouter, target, &ev)?;
    std_lib.assert_false(layouter, &is_less)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MidnightCircuit, PublicInputInstructions, Relation, Value, ZkStdLibArch};
    use midnight_proofs::dev::MockProver;
    use midnight_zk_stdlib as zk;

    #[derive(Clone, Default)]
    pub struct TestCircuit;

    impl Relation for TestCircuit {
        type Error = Error;

        type Instance = F;

        type Witness = (F, F);

        fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
            Ok(vec![*instance])
        }

        fn circuit(
            &self,
            std_lib: &ZkStdLib,
            layouter: &mut impl Layouter<F>,
            _instance: Value<Self::Instance>,
            witness: Value<Self::Witness>,
        ) -> Result<(), Error> {
            // Assign the two native base-field values to compare.
            let (a, b) = witness.unzip();
            let x = std_lib.assign(layouter, a)?;
            let y = std_lib.assign(layouter, b)?;

            std_lib.constrain_as_public_input(layouter, &x)?;

            let is_lower = lower_than_native(std_lib, layouter, &x, &y)?;
            std_lib.assert_true(layouter, &is_lower)
        }

        fn used_chips(&self) -> ZkStdLibArch {
            ZkStdLibArch {
                jubjub: true,
                poseidon: false,
                sha2_256: false,
                sha2_512: false,
                keccak_256: false,
                sha3_256: false,
                secp256k1: false,
                p256: false,
                curve25519: false,
                bls12_381: false,
                base64: false,
                nr_pow2range_cols: 2,
                nb_arith_cols: 5,
                automaton: false,
                blake2b: false,
            }
        }

        fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
            Ok(())
        }

        fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
            Ok(TestCircuit)
        }
    }

    #[test]
    fn test_lower_than() {
        const K: u32 = 9;
        let relation = TestCircuit;

        {
            let circuit = MidnightCircuit::from_relation(&relation, Some(K));
            println!("k {:?}", circuit.k());
            println!("{:?}", zk::cost_model(&relation, Some(K), false));
        }

        {
            let witness = (-F::from(5u64), -F::from(2u64));
            let instance = witness.0;

            let circuit = MidnightCircuit::new(
                &relation,
                Value::known(instance),
                Value::known(witness),
                Some(K),
            );
            let prover = match MockProver::run(&circuit, vec![vec![], vec![instance]]) {
                Ok(prover) => prover,
                Err(e) => panic!("{e:?}"),
            };
            assert!(prover.verify().is_ok());
        }

        {
            let witness = (-F::from(5u64), -F::from(22u64));
            let instance = witness.0;

            let circuit = MidnightCircuit::new(
                &relation,
                Value::known(instance),
                Value::known(witness),
                Some(K),
            );
            let prover = match MockProver::run(&circuit, vec![vec![], vec![instance]]) {
                Ok(prover) => prover,
                Err(e) => panic!("{e:?}"),
            };
            assert!(prover.verify().is_err());
        }
    }
}
