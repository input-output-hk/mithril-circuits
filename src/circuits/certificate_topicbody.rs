//! Certificate relation with separate topic and full-message signatures.
//!
//! Public inputs are `(registry_root, topic, body)`. Topic signatures cover
//! `[registry_root, topic]` and supply the lottery tag. Full-message signatures
//! cover `[registry_root, topic, body]` under the same registered key. Changing
//! the body therefore requires a new full-message signature while preserving
//! the topic's lottery values. Winning indices, rather than keys, are distinct.
//! Both signatures use the compact Schnorr representation from
//! [`crate::schnorr_signature`].

use crate::{
    AssignedBit, AssignedNative, AssignedNativePoint, AssignedScalarOfNativeCurve,
    AssignmentInstructions, CircuitCurve, ConversionInstructions, DST_LOTTERY,
    DST_UNIQUE_SIGNATURE, Error, Layouter, LotteryIndex, MerkleRoot, Msg, PublicInputInstructions,
    Relation, Value, ZkStdLib, ZkStdLibArch,
    circuits::{
        AssignedUniqueSignature, C, F, verify_lottery, verify_merkle_path, verify_unique_signature,
    },
    merkle_tree::{MTLeaf, MerklePath},
    schnorr_signature::Signature,
};
use ff::Field;
use group::Group;

/// Circuit configuration fixing quorum, lottery count, and membership-path depth.
#[derive(Clone, Default, Debug)]
pub struct Certificate {
    // Required number of distinct winning lottery indices.
    quorum: u32,
    // Number of lottery indices available to each signer.
    num_lotteries: u32,
    merkle_tree_depth: u32,
}

impl Certificate {
    /// Creates a circuit configuration without validating its parameters.
    ///
    /// `quorum` counts distinct winning indices, not distinct keys. Each
    /// witness path must contain `merkle_tree_depth` siblings. Synthesis
    /// requires `quorum < num_lotteries`; callers should choose a positive
    /// quorum. The 16-bit comparisons require `num_lotteries < 2^16`.
    pub fn new(quorum: u32, num_lotteries: u32, merkle_tree_depth: u32) -> Self {
        Self {
            quorum,
            num_lotteries,
            merkle_tree_depth,
        }
    }
}

impl Relation for Certificate {
    type Error = Error;

    /// Public registry root, encoded topic, and encoded body, in public-input order.
    type Instance = (MerkleRoot, Msg, Msg);
    /// Private witness: a vector of tuples containing a leaf, path, topic signature,
    /// full-message signature, and index. The circuit enforces exactly `quorum` entries.
    /// The indices must be strictly increasing to ensure uniqueness.
    type Witness = Vec<(MTLeaf, MerklePath, Signature, Signature, LotteryIndex)>;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<F>, Error> {
        Ok(vec![instance.0, instance.1, instance.2])
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
            std_lib.assign_as_public_input(layouter, instance.map(|(x, _, _)| x))?;
        let msg_topic: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|(_, x, _)| x))?;
        let msg_body: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|(_, _, x)| x))?;

        // Hash the registry root and topic once for all topic-signature checks.
        let hash_topic =
            std_lib.hash_to_curve(layouter, &[merkle_root.clone(), msg_topic.clone()])?;

        // Hash the registry root, topic, and body once for all full-message signature checks.
        let hash_body = std_lib.hash_to_curve(
            layouter,
            &[merkle_root.clone(), msg_topic.clone(), msg_body.clone()],
        )?;

        let generator: AssignedNativePoint<C> = std_lib.jubjub().assign_fixed(
            layouter,
            <C as CircuitCurve>::CryptographicGroup::generator(),
        )?;

        // Assign domain separation tags for signature and lottery hashing.
        let dst_signature: AssignedNative<_> =
            std_lib.assign_fixed(layouter, DST_UNIQUE_SIGNATURE)?;
        let dst_lottery: AssignedNative<_> = std_lib.assign_fixed(layouter, DST_LOTTERY)?;
        let lottery_prefix = std_lib.poseidon(
            layouter,
            &[dst_lottery.clone(), merkle_root.clone(), msg_topic.clone()],
        )?;

        // Ensure that the witness comprises exactly `quorum` entries.
        let witness = witness.transpose_vec(self.quorum as usize);

        let mut pre_index: AssignedNative<_> = std_lib.assign(layouter, Value::known(F::ZERO))?;
        for (i, wit) in witness.into_iter().enumerate() {
            let index: AssignedNative<F> = std_lib.assign(
                layouter,
                wit.clone().map(|(_, _, _, _, i)| F::from(i as u64)),
            )?;

            // Enforce strictly increasing indices to ensure uniqueness.
            if i > 0 {
                let is_less = std_lib.lower_than(layouter, &pre_index, &index, 16)?;
                std_lib.assert_true(layouter, &is_less)?;
            }

            pre_index = index.clone();

            let vk = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(x, _, _, _, _)| x.0.0))?;

            let target: AssignedNative<F> =
                std_lib.assign(layouter, wit.clone().map(|(x, _, _, _, _)| x.1))?;

            // ----------------- Verify Merkle Path -----------------
            // Assign sibling values.
            let assigned_merkle_siblings = std_lib.assign_many(
                layouter,
                wit.clone()
                    .map(|(_, x, _, _, _)| x.siblings.iter().map(|x| x.1).collect::<Vec<_>>())
                    .transpose_vec(self.merkle_tree_depth as usize)
                    .as_slice(),
            )?;

            // Assign sibling positions.
            let assigned_merkle_positions = std_lib.assign_many(
                layouter,
                wit.clone()
                    .map(|(_, x, _, _, _)| {
                        x.siblings.iter().map(|x| x.0.into()).collect::<Vec<_>>()
                    })
                    .transpose_vec(self.merkle_tree_depth as usize)
                    .as_slice(),
            )?;

            // Assert that Merkle path positions are binary values.
            let assigned_merkle_positions = assigned_merkle_positions
                .iter()
                .map(|pos| std_lib.convert(layouter, pos))
                .collect::<Result<Vec<AssignedBit<F>>, Error>>()?;

            verify_merkle_path(
                std_lib,
                layouter,
                &vk,
                &target,
                &merkle_root,
                &assigned_merkle_siblings,
                &assigned_merkle_positions,
            )?;

            // ----------------- Verify Topic Signature -----------------
            let sigma_topic: AssignedNativePoint<_> = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(_, _, sig, _, _)| sig.sigma))?;
            let s_topic: AssignedScalarOfNativeCurve<C> = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(_, _, sig, _, _)| sig.s))?;
            let c_native_topic =
                std_lib.assign(layouter, wit.clone().map(|(_, _, sig, _, _)| sig.c))?;
            let c_topic: AssignedScalarOfNativeCurve<C> =
                std_lib.jubjub().convert(layouter, &c_native_topic)?;

            verify_unique_signature(
                std_lib,
                layouter,
                &dst_signature,
                &generator,
                &vk,
                &hash_topic,
                AssignedUniqueSignature {
                    sigma: &sigma_topic,
                    s: &s_topic,
                    c: &c_topic,
                    c_native: &c_native_topic,
                },
            )?;

            // ----------------- Verify Body Signature -----------------
            let sigma_body: AssignedNativePoint<_> = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(_, _, _, sig, _)| sig.sigma))?;
            let s_body: AssignedScalarOfNativeCurve<C> = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(_, _, _, sig, _)| sig.s))?;
            let c_native_body = std_lib.assign(layouter, wit.map(|(_, _, _, sig, _)| sig.c))?;
            let c_body: AssignedScalarOfNativeCurve<C> =
                std_lib.jubjub().convert(layouter, &c_native_body)?;

            verify_unique_signature(
                std_lib,
                layouter,
                &dst_signature,
                &generator,
                &vk,
                &hash_body,
                AssignedUniqueSignature {
                    sigma: &sigma_body,
                    s: &s_body,
                    c: &c_body,
                    c_native: &c_native_body,
                },
            )?;

            // ----------------- Verify Lottery Eligibility -----------------
            verify_lottery(
                std_lib,
                layouter,
                &lottery_prefix,
                &sigma_topic,
                &index,
                &target,
            )?;
        }

        // Ensure that the last index is less than `num_lotteries` (= m).
        // m can be supplied as a public input or fixed as a constant.
        let m = std_lib.assign_fixed(layouter, F::from(self.num_lotteries as u64))?;
        let is_less = std_lib.lower_than(layouter, &pre_index, &m, 16)?;

        std_lib.assert_true(layouter, &is_less)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            poseidon: true,
            sha2_256: false,
            sha2_512: false,
            sha3_256: false,
            keccak_256: false,
            blake2b: false,
            secp256k1: false,
            p256: false,
            curve25519: false,
            bls12_381: false,
            base64: false,
            nb_arith_cols: 5,
            nr_pow2range_cols: 2,
            automaton: false,
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
    use crate::{
        circuits::test_srs::load_srs,
        merkle_tree::MerkleTree,
        schnorr_signature::{SigningKey, VerificationKey},
    };
    use ff::Field;
    use midnight_proofs::utils::SerdeFormat;
    use midnight_zk_stdlib as zk;
    use midnight_zk_stdlib::MidnightCircuit;
    use rand_core::OsRng;
    use std::io::Cursor;
    use std::time::Instant;

    fn create_merkle_tree(n: usize) -> (Vec<SigningKey>, Vec<MTLeaf>, MerkleTree) {
        //  let mut rng = ChaCha20Rng::seed_from_u64(1234);
        let mut rng = OsRng;

        let mut sks = Vec::new();
        let mut leaves = Vec::new();
        for _ in 0..n {
            let sk = SigningKey::generate(&mut rng);
            let vk = VerificationKey::from(&sk);
            leaves.push(MTLeaf(vk, -F::ONE));
            sks.push(sk);
        }
        let tree = MerkleTree::create(&leaves);

        (sks, leaves, tree)
    }

    fn run_certificate_case(case_name: &str, k: u32, quorum: u32) {
        let srs = load_srs(k);

        // Keep num_signers fixed for baseline comparisons.
        let num_signers: usize = 3000;
        let depth = num_signers.next_power_of_two().trailing_zeros();
        let num_lotteries = quorum * 10;
        let relation = Certificate::new(quorum, num_lotteries, depth);

        let (sks, leaves, merkle_tree) = create_merkle_tree(num_signers);

        {
            // Print circuit sizing information.
            let circuit = MidnightCircuit::from_relation(&relation, None);
            println!("\n=== Certificate case: {case_name} ===");
            println!("k (selected) {k}");
            println!("quorum {quorum}");
            println!("optimal_k {:?}", circuit.k());
            println!("{:?}", zk::cost_model(&relation, Some(k), false));
        }

        let start = Instant::now();
        let vk = zk::setup_vk(&srs, &relation);
        let pk = zk::setup_pk(&relation, &vk);
        let duration = start.elapsed();
        println!("\nvk pk generation took: {:?}", duration);

        {
            let mut buffer = Cursor::new(Vec::new());
            // Serialize the MidnightVK instance to the buffer in the RawBytes format.
            vk.write(&mut buffer, SerdeFormat::RawBytes).unwrap();
            // Get the size of the serialized MidnightVK.
            println!("vk length {:?}", buffer.get_ref().len());
        }

        let merkle_root = merkle_tree.root();
        // Message to be signed.
        let msg_topic = F::from(10);
        let msg_body = F::from(42);

        // Take the first few signers.
        let mut witness = vec![];
        for i in 0..quorum as usize {
            let ii = i % num_signers;
            let usk = sks[ii].clone();
            let uvk = leaves[ii].0;
            let sig_topic = usk.sign(&[merkle_root, msg_topic], &mut OsRng);
            sig_topic.verify(&[merkle_root, msg_topic], &uvk).unwrap();
            let sig_body = usk.sign(&[merkle_root, msg_topic, msg_body], &mut OsRng);
            sig_body
                .verify(&[merkle_root, msg_topic, msg_body], &uvk)
                .unwrap();

            let merkle_path = merkle_tree.get_path(ii);
            let computed_root = merkle_path.compute_root(leaves[ii]);
            assert_eq!(merkle_root, computed_root);

            // Every index is eligible because the target is set to the maximum.
            witness.push((leaves[ii], merkle_path, sig_topic, sig_body, (i + 1) as u32));
        }

        let instance = (merkle_root, msg_topic, msg_body);

        let start = Instant::now();
        let proof = zk::prove::<Certificate, blake2b_simd::State>(
            &srs, &pk, &relation, &instance, witness, OsRng,
        )
        .expect("Proof generation should not fail");
        let duration = start.elapsed();
        println!("\nProof generation took: {:?}", duration);
        println!("Proof size: {:?}", proof.len());

        let start = Instant::now();
        assert!(
            zk::verify::<Certificate, blake2b_simd::State>(
                &srs.verifier_params(),
                &vk,
                &instance,
                None,
                &proof
            )
            .is_ok()
        );
        let duration = start.elapsed();
        println!("Proof verification took: {:?}", duration);
    }

    #[test]
    fn test_certificate_small() {
        const K: u32 = 14;
        const QUORUM: u32 = 3;
        run_certificate_case("small", K, QUORUM);
    }

    #[test]
    fn test_certificate_medium() {
        const K: u32 = 17;
        const QUORUM: u32 = 32;
        run_certificate_case("medium", K, QUORUM);
    }

    #[test]
    fn test_certificate_large() {
        const K: u32 = 22;
        const QUORUM: u32 = 1024;
        run_certificate_case("large", K, QUORUM);
    }
}
