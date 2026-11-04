use crate::{
    ArithInstructions, AssertionInstructions, AssignedBit, AssignedNative, AssignedNativePoint,
    AssignedScalarOfNativeCurve, AssignmentInstructions, BinaryInstructions,
    ControlFlowInstructions, DecompositionInstructions, EccInstructions, EqualityInstructions,
    Error, Jubjub, JubjubBase, Layouter, ZkStdLib, utils::split,
};
use ff::{Field, PrimeField};

pub mod certificate;
pub mod fixed_bases;
pub mod ivc_one;

type F = JubjubBase;
type C = Jubjub;

/// Prefix applied (see [`fixed_bases::relabel`]) to the fixed-base labels of
/// the certificate verifying key when its proofs are folded into an
/// accumulator together with proofs of an IVC circuit.
pub const CERT_VK_NAME: &str = "cert_vk";
/// Name of the `ivc_one` verifying key. Its fixed bases keep the native
/// `midnight-circuits` labels, so this is informational only.
pub const IVC_ONE_NAME: &str = "ivc_one_vk";

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

// Decompose a 255-bit value into 127-bit and 128-bit values without checking the bound
fn decompose_unsafe(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    x: &AssignedNative<F>,
) -> Result<(AssignedNative<F>, AssignedNative<F>), Error> {
    // Decompose 255-bit value into 127-bit and 128-bit values.
    let x_value = x.value();
    let base127 = F::from_u128(1_u128 << 127);
    let (x_low, x_high) = x_value.map(|v| split(v, 127)).unzip();

    let x_low_assigned: AssignedNative<_> = std_lib.assign(layouter, x_low.clone())?;
    let x_high_assigned: AssignedNative<_> = std_lib.assign(layouter, x_high.clone())?;

    let x_combined: AssignedNative<_> = std_lib.linear_combination(
        layouter,
        &[
            (F::ONE, x_low_assigned.clone()),
            (base127, x_high_assigned.clone()),
        ],
        F::ZERO,
    )?;
    std_lib.assert_equal(layouter, x, &x_combined)?;

    // Verify the least significant bit is consistent to make sure the decomposition is unique
    // This works because the modulus is an odd number
    assert_equal_parity(std_lib, layouter, &x, &x_low_assigned)?;

    Ok((x_low_assigned, x_high_assigned))
}

// Compare x < y where x, y are 255-bit
fn lower_than_native(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    x: &AssignedNative<F>,
    y: &AssignedNative<F>,
) -> Result<AssignedBit<F>, Error> {
    let (x_low_assigned, x_high_assigned) = decompose_unsafe(std_lib, layouter, x)?;
    let (y_low_assigned, y_high_assigned) = decompose_unsafe(std_lib, layouter, y)?;

    // Check if x < y
    let is_equal_high = std_lib.is_equal(layouter, &x_high_assigned, &y_high_assigned)?;
    let is_less_low = std_lib.lower_than(layouter, &x_low_assigned, &y_low_assigned, 127)?;
    let is_less_high = std_lib.lower_than(layouter, &x_high_assigned, &y_high_assigned, 128)?;

    let low_less = std_lib.and(layouter, &[is_equal_high, is_less_low])?;
    std_lib.or(layouter, &[is_less_high, low_less])
}

fn verify_merkle_path(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    vk: &AssignedNativePoint<C>,
    target: &AssignedNative<F>,
    merkle_root: &AssignedNative<F>,
    merkle_siblings: &[AssignedNative<F>],
    merkle_positions: &[AssignedBit<F>],
) -> Result<(), Error> {
    let vk_x = std_lib.jubjub().x_coordinate(&vk);
    let vk_y = std_lib.jubjub().y_coordinate(&vk);
    let leaf = std_lib.poseidon(layouter, &[vk_x.clone(), vk_y.clone(), target.clone()])?;
    let root = merkle_siblings
        .iter()
        .zip(merkle_positions.iter())
        .try_fold(leaf, |acc, (x, pos)| {
            // Choose the left child for hashing:
            // If pos is 1 (sibling on right) choose the current node else the sibling.
            let left = std_lib.select(layouter, pos, &acc, x)?;

            // Choose the right child for hashing:
            // If pos is 1 (sibling on right) choose the sibling else the current node.
            let right = std_lib.select(layouter, pos, x, &acc)?;

            std_lib.poseidon(layouter, &[left, right])
        })?;

    std_lib.assert_equal(layouter, &root, merkle_root)
}

fn verify_unique_signature(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<F>,
    dst_signature: &AssignedNative<F>,
    generator: &AssignedNativePoint<C>,
    vk: &AssignedNativePoint<C>,
    s: &AssignedScalarOfNativeCurve<C>,
    c: &AssignedScalarOfNativeCurve<C>,
    c_native: &AssignedNative<F>,
    hash: &AssignedNativePoint<C>,
    sigma: &AssignedNativePoint<C>,
) -> Result<(), Error> {
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

    // Compute H2(g, H1(msg), vk, sigma, R1, R2)
    let hx = std_lib.jubjub().x_coordinate(&hash);
    let hy = std_lib.jubjub().y_coordinate(&hash);
    let vk_x = std_lib.jubjub().x_coordinate(&vk);
    let vk_y = std_lib.jubjub().y_coordinate(&vk);
    let sigma_x = std_lib.jubjub().x_coordinate(&sigma);
    let sigma_y = std_lib.jubjub().y_coordinate(&sigma);
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
    let is_less = lower_than_native(std_lib, layouter, &target, &ev)?;
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
        type Instance = F;

        type Witness = (F, F);

        type Error = Error;

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
            // First we witness a Scalar.
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
                nb_arith_cols: 5,
                nr_pow2range_cols: 2,
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
            let circuit = MidnightCircuit::from_relation(&relation, None);
            println!("k (optimal) {:?}", circuit.k());
            println!("{:?}", zk::cost_model(&relation, None, false));
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
