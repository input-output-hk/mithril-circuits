use crate::{
    ArithInstructions, AssertionInstructions, AssignedBit, AssignedNative, AssignedNativePoint,
    AssignmentInstructions, BinaryInstructions, ControlFlowInstructions, ConversionInstructions,
    EccInstructions, EqualityInstructions, Error, Index, Jubjub, JubjubBase, JubjubSubgroup,
    Layouter, MerkleRoot, Msg, PublicInputInstructions, Relation, ScalarVar, Signature, Value,
    ZkStdLib, ZkStdLibArch,
};
use ff::{Field, PrimeField};

use crate::merkle_tree::{MTLeaf, MerklePath};
use crate::utils::decompose;
use group::Group;

type F = JubjubBase;

#[derive(Clone, Default, Debug)]
pub struct Certificate {
    quorum: u32,
    num_lotteries: u32,
    merkle_tree_depth: u32,
}

impl Certificate {
    pub fn new(quorum: u32, num_lotteries: u32, merkle_tree_depth: u32) -> Self {
        Self {
            quorum,
            num_lotteries,
            merkle_tree_depth,
        }
    }
}

impl Relation for Certificate {
    type Instance = (MerkleRoot, Msg);
    type Witness = Vec<(MTLeaf, MerklePath, Signature, Index)>;

    fn format_instance(instance: &Self::Instance) -> Vec<F> {
        vec![instance.0, instance.1]
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        assert!(self.quorum < self.num_lotteries);

        let merkle_root: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|(x, _)| x))?;
        let msg: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|(_, x)| x))?;

        // Compute H_1(msg)
        let hash = std_lib.hash_to_curve(layouter, &[msg.clone()])?;

        let generator: AssignedNativePoint<Jubjub> = std_lib
            .jubjub()
            .assign_fixed(layouter, <JubjubSubgroup as Group>::generator())?;

        let witness = witness.transpose_vec(self.quorum as usize);

        let mut pre_index: AssignedNative<_> = std_lib.assign(layouter, Value::known(F::ZERO))?;
        for (i, wit) in witness.into_iter().enumerate() {
            let index: AssignedNative<F> =
                std_lib.assign(layouter, wit.clone().map(|(_, _, _, i)| F::from(i as u64)))?;

            if i > 0 {
                let is_less = std_lib.lower_than(layouter, &pre_index, &index, 32)?;
                std_lib.assert_true(layouter, &is_less)?;
            }

            pre_index = index.clone();

            let vk = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(x, _, _, _)| x.0.0))?;

            let target: AssignedNative<F> =
                std_lib.assign(layouter, wit.clone().map(|(x, _, _, _)| x.1))?;

            // Assign sibling Values.
            let assigned_merkle_siblings = std_lib.assign_many(
                layouter,
                wit.clone()
                    .map(|(_, x, _, _)| x.siblings.iter().map(|x| x.1).collect::<Vec<_>>())
                    .transpose_vec(self.merkle_tree_depth as usize)
                    .as_slice(),
            )?;

            // Assign sibling Position.
            let assigned_merkle_positions = std_lib.assign_many(
                layouter,
                wit.clone()
                    .map(|(_, x, _, _)| x.siblings.iter().map(|x| x.0.into()).collect::<Vec<_>>())
                    .transpose_vec(self.merkle_tree_depth as usize)
                    .as_slice(),
            )?;

            // Assert merkle positions are binary values.
            let assigned_merkle_positions = assigned_merkle_positions
                .iter()
                .map(|pos| std_lib.convert(layouter, pos))
                .collect::<Result<Vec<AssignedBit<F>>, Error>>()?;

            let sigma = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(_, _, sig, _)| sig.sigma))?;
            let s: ScalarVar<Jubjub> = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(_, _, sig, _)| sig.s))?;
            let c_native = std_lib.assign(layouter, wit.map(|(_, _, sig, _)| sig.c))?;
            let c: ScalarVar<Jubjub> = std_lib.jubjub().convert(layouter, &c_native)?;

            let vk_x = std_lib.jubjub().x_coordinate(&vk);
            let vk_y = std_lib.jubjub().y_coordinate(&vk);

            // ---------------------- Verify merkle path ----------------------
            let leaf = std_lib.poseidon(layouter, &[vk_x.clone(), vk_y.clone(), target.clone()])?;
            let root = assigned_merkle_siblings
                .iter()
                .zip(assigned_merkle_positions.iter())
                .try_fold(leaf, |acc, (x, pos)| {
                    // Choose the left child for hashing:
                    // If pos is 1 (sibling on right) choose the current node else the sibling.
                    let left = std_lib.select(layouter, pos, &acc, x)?;

                    // Choose the right child for hashing:
                    // If pos is 1 (sibling on right) choose the sibling else the current node.
                    let right = std_lib.select(layouter, pos, x, &acc)?;

                    std_lib.poseidon(layouter, &[left, right])
                })?;

            std_lib.assert_equal(layouter, &root, &merkle_root)?;

            // ---------------------- Verify signature ----------------------
            // compute R1
            let sigma_neg = std_lib.jubjub().negate(layouter, &sigma)?;
            let cap_r_1 = std_lib.jubjub().msm(
                layouter,
                &[s.clone(), c.clone()],
                &[hash.clone(), sigma_neg],
            )?;

            // compute R2
            let vk_neg = std_lib.jubjub().negate(layouter, &vk)?;
            let cap_r_2 = std_lib
                .jubjub()
                .msm(layouter, &[s, c], &[generator.clone(), vk_neg])?;

            // compute H2(g, H1(msg), vk, sigma, R1, R2)
            let gx = std_lib.jubjub().x_coordinate(&generator);
            let gy = std_lib.jubjub().y_coordinate(&generator);
            let hx = std_lib.jubjub().x_coordinate(&hash);
            let hy = std_lib.jubjub().y_coordinate(&hash);
            let sigma_x = std_lib.jubjub().x_coordinate(&sigma);
            let sigma_y = std_lib.jubjub().y_coordinate(&sigma);
            let cap_r_1_x = std_lib.jubjub().x_coordinate(&cap_r_1);
            let cap_r_1_y = std_lib.jubjub().y_coordinate(&cap_r_1);
            let cap_r_2_x = std_lib.jubjub().x_coordinate(&cap_r_2);
            let cap_r_2_y = std_lib.jubjub().y_coordinate(&cap_r_2);

            let c_prime = std_lib.poseidon(
                layouter,
                &[
                    gx,
                    gy,
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
            std_lib.assert_equal(layouter, &c_native, &c_prime)?;

            // ---------------------- Check lottery eligibility ----------------------
            let ev = std_lib.poseidon(layouter, &[msg.clone(), sigma_x, sigma_y, index])?;
            let ev_value = ev.value();
            // decompose 255-bit value into 3 85-bit values.
            let base85 = F::from_u128(1_u128 << 85);
            let base170 = base85.square();

            let ev_decomposed = ev_value.map(|v| decompose(v)).transpose_vec(3);
            let ev_limb1_assigned: AssignedNative<F> =
                std_lib.assign(layouter, ev_decomposed[0].clone())?;
            let ev_limb2_assigned: AssignedNative<F> =
                std_lib.assign(layouter, ev_decomposed[1].clone())?;
            let ev_limb3_assigned: AssignedNative<F> =
                std_lib.assign(layouter, ev_decomposed[2].clone())?;

            let ev_combined = std_lib.linear_combination(
                layouter,
                &[
                    (F::ONE, ev_limb1_assigned.clone()),
                    (base85, ev_limb2_assigned.clone()),
                    (base170, ev_limb3_assigned.clone()),
                ],
                F::ZERO,
            )?;
            std_lib.assert_equal(layouter, &ev, &ev_combined)?;

            let target_value = target.value();
            let target_decomposed = target_value.map(|v| decompose(v)).transpose_vec(3);
            let target_limb1_assigned: AssignedNative<F> =
                std_lib.assign(layouter, target_decomposed[0].clone())?;
            let target_limb2_assigned: AssignedNative<F> =
                std_lib.assign(layouter, target_decomposed[1].clone())?;
            let target_limb3_assigned: AssignedNative<F> =
                std_lib.assign(layouter, target_decomposed[2].clone())?;

            let target_combined = std_lib.linear_combination(
                layouter,
                &[
                    (F::ONE, target_limb1_assigned.clone()),
                    (base85, target_limb2_assigned.clone()),
                    (base170, target_limb3_assigned.clone()),
                ],
                F::ZERO,
            )?;
            std_lib.assert_equal(layouter, &target, &target_combined)?;

            // Check if ev <= target by asserting target < ev is false
            let is_equal_3 =
                std_lib.is_equal(layouter, &target_limb3_assigned, &ev_limb3_assigned)?;
            let is_less_3 =
                std_lib.lower_than(layouter, &target_limb3_assigned, &ev_limb3_assigned, 85)?;
            let is_equal_2 =
                std_lib.is_equal(layouter, &target_limb2_assigned, &ev_limb2_assigned)?;
            let is_less_2 =
                std_lib.lower_than(layouter, &target_limb2_assigned, &ev_limb2_assigned, 85)?;
            let is_less_1 =
                std_lib.lower_than(layouter, &target_limb1_assigned, &ev_limb1_assigned, 85)?;

            let less1 = std_lib.and(layouter, &[is_equal_2, is_less_1])?;
            let less2 = std_lib.or(layouter, &[is_less_2, less1])?;
            let less23 = std_lib.and(layouter, &[is_equal_3, less2])?;
            let less = std_lib.or(layouter, &[is_less_3, less23])?;

            std_lib.assert_false(layouter, &less)?;
        }

        // m can be put as a public instance or a constant
        let m = std_lib.assign_fixed(layouter, F::from(self.num_lotteries as u64))?;
        let is_less = std_lib.lower_than(layouter, &pre_index, &m, 32)?;

        std_lib.assert_true(layouter, &is_less)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            poseidon: true,
            sha256: None,
            secp256k1: false,
            bls12_381: false,
            base64: false,
        }
    }

    fn write_relation<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.quorum.to_le_bytes())?;
        writer.write_all(&self.num_lotteries.to_le_bytes())?;
        writer.write_all(&self.merkle_tree_depth.to_le_bytes())
    }

    fn read_relation<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Buffers to read 4 bytes for each `u32` field.
        let mut quorum_bytes = [0u8; 4];
        let mut num_lotteries_bytes = [0u8; 4];
        let mut merkle_tree_depth_bytes = [0u8; 4];

        // Read the values into their corresponding buffers.
        reader.read_exact(&mut quorum_bytes)?;
        reader.read_exact(&mut num_lotteries_bytes)?;
        reader.read_exact(&mut merkle_tree_depth_bytes)?;

        // Convert the byte arrays back into `u32` values.
        let quorum = u32::from_le_bytes(quorum_bytes);
        let num_lotteries = u32::from_le_bytes(num_lotteries_bytes);
        let merkle_tree_depth = u32::from_le_bytes(merkle_tree_depth_bytes);

        // Construct and return the `Certificate` instance.
        Ok(Self {
            quorum,
            num_lotteries,
            merkle_tree_depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::Certificate;
    use crate::merkle_tree::MerkleTree;
    use crate::{BlstG1, MidnightCircuit, SigningKey, VerificationKey, compact_std_lib};
    use blstrs::Bls12;
    use ff::Field;
    use midnight_circuits::testing_utils::plonk_api::filecoin_srs;
    use midnight_proofs::dev::CircuitCost;
    use midnight_proofs::poly::kzg::params::ParamsKZG;
    use midnight_proofs::utils::SerdeFormat;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;
    use rand_core::OsRng;
    use std::fs::File;
    use std::io::BufReader;
    use std::time::Instant;

    fn create_merkle_tree(n: usize) -> (Vec<SigningKey>, Vec<MTLeaf>, MerkleTree) {
        //  let mut rng = ChaCha20Rng::seed_from_u64(1234);
        let mut rng = OsRng;

        let mut sks = Vec::new();
        let mut leaves = Vec::new();
        for i in 0..n {
            let sk = SigningKey::generate(&mut rng);
            let vk = VerificationKey::from(&sk); // Replace this with actual initialization if provided
            leaves.push(MTLeaf(vk, -F::ONE));
            sks.push(sk);
        }
        let tree = MerkleTree::create(&leaves);

        (sks, leaves, tree)
    }

    fn open(k: u32) -> ParamsKZG<Bls12> {
        let path = format!("examples/assets/params_kzg_unsafe_{}", k);
        let file = File::open(path).unwrap();
        let mut reader = BufReader::new(file);
        let params: ParamsKZG<Bls12> =
            ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap();

        params
    }

    #[test]
    fn test_certificate() {
        const K: u32 = 13;
        let srs = filecoin_srs(K);
        // let srs = open(K);

        let num_signers: usize = 3000;
        let depth = num_signers.next_power_of_two().trailing_zeros();
        let quorum = 3;
        let num_lotteries = quorum * 10;
        let relation = Certificate::new(quorum, num_lotteries, depth);
        println!("Circuit {:?}", relation);

        let (sks, leaves, merkle_tree) = create_merkle_tree(num_signers);

        {
            // print circuit size
            let circuit = MidnightCircuit::from_relation(&relation);
            let cost = CircuitCost::<BlstG1, _>::measure(K, &circuit);
            println!("Circuit cost: {:?}", cost);
        }

        let start = Instant::now();
        let vk = compact_std_lib::setup_vk(&srs, &relation);
        let pk = compact_std_lib::setup_pk(&relation, &vk);
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("\nvk pk generation took: {:?}", duration);

        let merkle_root = merkle_tree.root();
        // message to be signed
        let msg = F::from(42);

        // take the first few signers
        let mut witness = vec![];
        for i in 0..quorum as usize {
            let usk = sks[i].clone();
            let uvk = leaves[i].0;
            let sig = usk.sign(msg, &mut OsRng);
            sig.verify(msg, &uvk).unwrap();

            let merkle_path = merkle_tree.get_path(i);
            let computed_root = merkle_path.compute_root(leaves[i]);
            assert_eq!(merkle_root, computed_root);

            // any index is eligible as target is set to be the maximum
            witness.push((leaves[i], merkle_path, sig, (i + 1) as u32));
        }

        let instance = (merkle_root, msg);

        let start = Instant::now();
        let proof = compact_std_lib::prove::<Certificate, blake2b_simd::State>(
            &srs, &pk, &relation, &instance, witness, OsRng,
        )
        .expect("Proof generation should not fail");
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("\nProof generation took: {:?}", duration);

        println!("\nproof size: {:?}", proof.len());

        let start = Instant::now();
        assert!(
            compact_std_lib::verify::<Certificate, blake2b_simd::State>(
                &srs.verifier_params(),
                &vk,
                &instance,
                &proof
            )
            .is_ok()
        );
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("\nProof verification took: {:?}", duration);
    }
}
