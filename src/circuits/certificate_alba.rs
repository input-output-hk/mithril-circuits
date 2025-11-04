use crate::merkle_tree::{MTLeaf, MerklePath};
use crate::utils::{big_to_fe, split};
use crate::{
    ArithInstructions, AssertionInstructions, AssignedBit, AssignedNative, AssignedNativePoint,
    AssignmentInstructions, ControlFlowInstructions, ConversionInstructions, DST_ALBA_BIN,
    DST_ALBA_FINAL, DST_ALBA_ROUND, DST_LOTTERY, DST_SIGNATURE, EccInstructions, Error, Jubjub,
    JubjubBase, JubjubSubgroup, Layouter, LotteryIndex, MerkleRoot, Msg, PublicInputInstructions,
    RangeCheckInstructions, Relation, ScalarVar, Signature, Value, ZkStdLib, ZkStdLibArch,
    div_rem_native_by_base, lower_than_native,
};
use ff::{Field, PrimeField};
use group::Group;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One};
use std::ops::Div;

type F = JubjubBase;

// Alba truncated hash length
const ALBA_NUM_LOW_BITS: u32 = 128;
const ALBA_NUM_HIGH_BITS: u32 = F::NUM_BITS - ALBA_NUM_LOW_BITS;

#[derive(Clone, Default, Debug)]
pub struct AlbaParams {
    // u in alba
    proof_size: u32,
    search_width: u32,
    max_retries: u32,
    set_size: u32,
    valid_proof_target: u128,
}

impl AlbaParams {
    pub fn new(
        proof_size: u32,
        search_width: u32,
        max_retries: u32,
        set_size: u32,
        valid_proof_target: u128,
    ) -> Self {
        Self {
            proof_size,
            search_width,
            max_retries,
            set_size,
            valid_proof_target,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct AlbaProofMeta {
    retry_counter: u32,
    search_counter: u32,
}

impl AlbaProofMeta {
    pub fn new(retry_counter: u32, search_counter: u32) -> Self {
        Self {
            retry_counter,
            search_counter,
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct Certificate {
    alba_params: AlbaParams,
    // m in mithril: the number of lotteries that a user can participate in to sign a message
    num_lotteries: u32,
    merkle_tree_depth: u32,
}

impl Certificate {
    pub fn new(alba_params: AlbaParams, num_lotteries: u32, merkle_tree_depth: u32) -> Self {
        Self {
            alba_params,
            num_lotteries,
            merkle_tree_depth,
        }
    }
}

impl Relation for Certificate {
    type Instance = (MerkleRoot, Msg);

    type Witness = (
        Vec<(MTLeaf, MerklePath, Signature, LotteryIndex)>,
        AlbaProofMeta,
    );

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
        assert!(self.alba_params.set_size > 1);

        let merkle_root: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|(x, _)| x))?;
        let msg: AssignedNative<F> =
            std_lib.assign_as_public_input(layouter, instance.map(|(_, x)| x))?;

        // Compute H_1(msg)
        let hash = std_lib.hash_to_curve(layouter, &[msg.clone()])?;

        let generator: AssignedNativePoint<Jubjub> = std_lib
            .jubjub()
            .assign_fixed(layouter, <JubjubSubgroup as Group>::generator())?;

        let dst_signature: AssignedNative<_> = std_lib.assign_fixed(layouter, DST_SIGNATURE)?;

        let lottery_index_bound = BigUint::from(self.num_lotteries as u64);
        let alba_search_width =
            std_lib.assign_fixed(layouter, F::from(self.alba_params.search_width as u64))?;
        let alba_max_retries: AssignedNative<_> =
            std_lib.assign_fixed(layouter, F::from(self.alba_params.max_retries as u64))?;
        let alba_search_counter: AssignedNative<_> = std_lib.assign(
            layouter,
            witness
                .clone()
                .map(|(_, x)| F::from(x.search_counter as u64)),
        )?;
        let alba_retry_counter: AssignedNative<_> = std_lib.assign(
            layouter,
            witness
                .clone()
                .map(|(_, x)| F::from(x.retry_counter as u64)),
        )?;

        let proofs = witness
            .clone()
            .map(|x| x.0)
            .transpose_vec(self.alba_params.proof_size as usize);

        // ---------------------- Verify Alba Proof Meta Data ----------------------
        {
            let is_less =
                std_lib.lower_than(layouter, &alba_search_counter, &alba_search_width, 32)?;
            std_lib.assert_true(layouter, &is_less)?;
            let is_less =
                std_lib.lower_than(layouter, &alba_retry_counter.clone(), &alba_max_retries, 32)?;
            std_lib.assert_true(layouter, &is_less)?;
        }

        // ---------------------- Verify Proofs ----------------------
        let dst_lottery: AssignedNative<_> = std_lib.assign_fixed(layouter, DST_LOTTERY)?;
        let dst_alba_round: AssignedNative<_> = std_lib.assign_fixed(layouter, DST_ALBA_ROUND)?;
        let dst_alba_bin: AssignedNative<_> = std_lib.assign_fixed(layouter, DST_ALBA_BIN)?;

        let mut alba_round_hash = std_lib.poseidon(
            layouter,
            &[
                dst_alba_round.clone(),
                alba_retry_counter.clone(),
                alba_search_counter,
            ],
        )?;

        let max_big: BigUint = BigUint::one() << ALBA_NUM_LOW_BITS;
        let alba_sample_bound = {
            let max_minus_1: BigUint = &max_big - BigUint::one();
            let d = max_minus_1.div(self.alba_params.set_size);
            let sample_bound = d * self.alba_params.set_size;
            sample_bound
        };
        let alba_base_low: F = big_to_fe(max_big);
        let alba_high_bound = BigUint::one() << ALBA_NUM_HIGH_BITS;

        for wit in proofs.into_iter() {
            // assert lottery_index < m
            let lottery_index: AssignedNative<F> = std_lib.assign_lower_than_fixed(
                layouter,
                wit.clone().map(|(_, _, _, i)| F::from(i as u64)),
                &lottery_index_bound,
            )?;

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
            let assigned_merkle_positions_bits = assigned_merkle_positions
                .iter()
                .map(|pos| std_lib.convert(layouter, pos))
                .collect::<Result<Vec<AssignedBit<F>>, Error>>()?;

            let sigma: AssignedNativePoint<_> = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(_, _, sig, _)| sig.sigma))?;
            let s: ScalarVar<Jubjub> = std_lib
                .jubjub()
                .assign(layouter, wit.clone().map(|(_, _, sig, _)| sig.s))?;
            let c_native = std_lib.assign(layouter, wit.map(|(_, _, sig, _)| sig.c))?;
            let c: ScalarVar<Jubjub> = std_lib.jubjub().convert(layouter, &c_native)?;

            let vk_x = std_lib.jubjub().x_coordinate(&vk);
            let vk_y = std_lib.jubjub().y_coordinate(&vk);

            // ---------------------- Verify Merkle Path ----------------------
            {
                let leaf =
                    std_lib.poseidon(layouter, &[vk_x.clone(), vk_y.clone(), target.clone()])?;
                let root = assigned_merkle_siblings
                    .iter()
                    .zip(assigned_merkle_positions_bits.iter())
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
            }

            // ---------------------- Verify Signature ----------------------
            {
                // compute R1
                let cap_r_1 = std_lib.jubjub().msm(
                    layouter,
                    &[s.clone(), c.clone()],
                    &[hash.clone(), sigma.clone()],
                )?;

                // compute R2
                let cap_r_2 = std_lib
                    .jubjub()
                    .msm(layouter, &[s, c], &[generator.clone(), vk])?;

                // compute H2(g, H1(msg), vk, sigma, R1, R2)
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
                std_lib.assert_equal(layouter, &c_native, &c_prime)?;
            }

            // ---------------------- Check Lottery Eligibility ----------------------
            {
                let sigma_x = std_lib.jubjub().x_coordinate(&sigma);
                let sigma_y = std_lib.jubjub().y_coordinate(&sigma);
                let ev = std_lib.poseidon(
                    layouter,
                    &[
                        dst_lottery.clone(),
                        msg.clone(),
                        sigma_x,
                        sigma_y,
                        lottery_index.clone(),
                    ],
                )?;
                let is_less = lower_than_native(std_lib, layouter, &target, &ev)?;
                std_lib.assert_false(layouter, &is_less)?;
            }

            //  ---------------------- Verify Alba Proof  ----------------------
            {
                let alba_bin_hash = std_lib.poseidon(
                    layouter,
                    &[
                        dst_alba_bin.clone(),
                        alba_retry_counter.clone(),
                        lottery_index.clone(),
                    ],
                )?;

                let round_hash_value = alba_round_hash.value();
                let bin_hash_value = alba_bin_hash.value();

                let (round_low, round_high) = round_hash_value
                    .map(|v| split(v, ALBA_NUM_LOW_BITS))
                    .unzip();
                let (bin_low, bin_high) =
                    bin_hash_value.map(|v| split(v, ALBA_NUM_LOW_BITS)).unzip();

                let round_high_assigned =
                    std_lib.assign_lower_than_fixed(layouter, round_high, &alba_high_bound)?;
                let bin_high_assigned =
                    std_lib.assign_lower_than_fixed(layouter, bin_high, &alba_high_bound)?;

                // assign lower bits: round_low < alba_sample_bound, bin_low < alba_sample_bound, alba_sample_bound = ((2^ALBA_NUM_LOW_BITS-1) / base)*base
                // this bound is sufficient because alba_sample_bound < 2^ALBA_NUM_LOW_BITS
                let round_low_assigned: AssignedNative<_> =
                    std_lib.assign_lower_than_fixed(layouter, round_low, &alba_sample_bound)?;
                let bin_low_assigned: AssignedNative<_> =
                    std_lib.assign_lower_than_fixed(layouter, bin_low, &alba_sample_bound)?;

                // verify alba_round_hash = round_low + (round_high << num_low_bits)
                let round_combined = std_lib.linear_combination(
                    layouter,
                    &[
                        (F::ONE, round_low_assigned.clone()),
                        (alba_base_low, round_high_assigned.clone()),
                    ],
                    F::ZERO,
                )?;
                std_lib.assert_equal(layouter, &alba_round_hash, &round_combined)?;

                // verify alba_bin_hash = bin_low + (bin_high << num_low_bits)
                let bin_combined = std_lib.linear_combination(
                    layouter,
                    &[
                        (F::ONE, bin_low_assigned.clone()),
                        (alba_base_low, bin_high_assigned.clone()),
                    ],
                    F::ZERO,
                )?;
                std_lib.assert_equal(layouter, &alba_bin_hash, &bin_combined)?;

                // verify round_low - bin_low = 0 (mod set_size)
                let (_, rem_round) = div_rem_native_by_base(
                    std_lib,
                    layouter,
                    &round_low_assigned,
                    ALBA_NUM_LOW_BITS,
                    self.alba_params.set_size,
                )?;
                let (_, rem_bin) = div_rem_native_by_base(
                    std_lib,
                    layouter,
                    &bin_low_assigned,
                    ALBA_NUM_LOW_BITS,
                    self.alba_params.set_size,
                )?;
                std_lib.assert_equal(layouter, &rem_round, &rem_bin)?;

                alba_round_hash = std_lib.poseidon(layouter, &[alba_round_hash, lottery_index])?;
            }
        }

        // ---------------------- Verify the Last Alba Hash ----------------------
        {
            let dst: AssignedNative<_> = std_lib.assign_fixed(layouter, DST_ALBA_FINAL)?;
            let proof_hash = std_lib.poseidon(layouter, &[dst, alba_round_hash.clone()])?;
            let proof_hash_value = proof_hash.value();
            let (proof_hash_low, proof_hash_high) = proof_hash_value
                .map(|v| split(v, ALBA_NUM_LOW_BITS))
                .unzip();
            // this bound is sufficient when num_bits(valid_proof_target) <= ALBA_NUM_LOW_BITS
            let proof_hash_low_assigned = std_lib.assign_lower_than_fixed(
                layouter,
                proof_hash_low,
                &BigUint::from_u128(self.alba_params.valid_proof_target).unwrap(),
            )?;
            let proof_hash_high_assigned =
                std_lib.assign_lower_than_fixed(layouter, proof_hash_high, &alba_high_bound)?;
            let combined = std_lib.linear_combination(
                layouter,
                &[
                    (F::ONE, proof_hash_low_assigned.clone()),
                    (alba_base_low, proof_hash_high_assigned.clone()),
                ],
                F::ZERO,
            )?;
            std_lib.assert_equal(layouter, &proof_hash, &combined)?;
        }

        Ok(())
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            poseidon: true,
            sha256: false,
            secp256k1: false,
            bls12_381: false,
            base64: false,
            nr_pow2range_cols: 1,
            automaton: false,
        }
    }

    fn write_relation<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.alba_params.proof_size.to_le_bytes())?;
        writer.write_all(&self.alba_params.search_width.to_le_bytes())?;
        writer.write_all(&self.alba_params.max_retries.to_le_bytes())?;
        writer.write_all(&self.alba_params.set_size.to_le_bytes())?;
        writer.write_all(&self.alba_params.valid_proof_target.to_le_bytes())?;

        writer.write_all(&self.num_lotteries.to_le_bytes())?;
        writer.write_all(&self.merkle_tree_depth.to_le_bytes())
    }

    fn read_relation<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // Buffers to read 4 bytes for each `u32` field.
        let mut proof_size_bytes = [0u8; 4];
        let mut search_width_bytes = [0u8; 4];
        let mut max_retries_bytes = [0u8; 4];
        let mut set_size_bytes = [0u8; 4];
        let mut valid_proof_targets_bytes = [0u8; 16];

        let mut quorum_bytes = [0u8; 4];
        let mut num_lotteries_bytes = [0u8; 4];
        let mut merkle_tree_depth_bytes = [0u8; 4];

        // Read the values into their corresponding buffers.
        reader.read_exact(&mut proof_size_bytes)?;
        reader.read_exact(&mut search_width_bytes)?;
        reader.read_exact(&mut max_retries_bytes)?;
        reader.read_exact(&mut set_size_bytes)?;
        reader.read_exact(&mut valid_proof_targets_bytes)?;

        reader.read_exact(&mut quorum_bytes)?;
        reader.read_exact(&mut num_lotteries_bytes)?;
        reader.read_exact(&mut merkle_tree_depth_bytes)?;

        // Convert the byte arrays back into `u32` values.
        let proof_size = u32::from_le_bytes(proof_size_bytes);
        let search_width = u32::from_le_bytes(search_width_bytes);
        let max_retries = u32::from_le_bytes(max_retries_bytes);
        let set_size = u32::from_le_bytes(set_size_bytes);
        let valid_proof_target = u128::from_le_bytes(valid_proof_targets_bytes);

        let num_lotteries = u32::from_le_bytes(num_lotteries_bytes);
        let merkle_tree_depth = u32::from_le_bytes(merkle_tree_depth_bytes);

        // Construct and return the `Certificate` instance.
        Ok(Self {
            alba_params: AlbaParams {
                proof_size,
                search_width,
                max_retries,
                set_size,
                valid_proof_target,
            },
            num_lotteries,
            merkle_tree_depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alba::{Element, Params as AlbaProofParams, Proof as AlbaProof, target};
    use crate::merkle_tree::MerkleTree;
    use crate::{Bls12, BlstG1, MidnightCircuit, SigningKey, VerificationKey};
    use ff::Field;
    use midnight_circuits::compact_std_lib;
    use midnight_circuits::testing_utils::plonk_api::filecoin_srs;
    use midnight_proofs::dev::CircuitCost;
    use midnight_proofs::poly::kzg::params::ParamsKZG;
    use midnight_proofs::utils::SerdeFormat;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;
    use rand_core::OsRng;
    use std::fs::File;
    use std::io::{BufReader, Cursor};
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

    fn create_proofs(
        num_signers: usize,
        set_size: u32,
        params: &AlbaProofParams,
    ) -> (
        <Certificate as Relation>::Instance,
        <Certificate as Relation>::Witness,
    ) {
        let (sks, leaves, merkle_tree) = create_merkle_tree(num_signers);
        let msg = F::from(42);
        let merkle_root = merkle_tree.root();

        let mut proofs = std::collections::HashMap::new();
        let mut indices = vec![];
        let mut prover_set = vec![];
        for i in 0..num_signers {
            let usk = sks[i].clone();
            let uvk = leaves[i].0;
            let sig = usk.sign(msg, &mut OsRng);
            sig.verify(msg, &uvk).unwrap();

            let merkle_path = merkle_tree.get_path(i);
            let computed_root = merkle_path.compute_root(leaves[i]);
            assert_eq!(merkle_root, computed_root);

            // any index is eligible as target is set to be the maximum
            let element = Element::new((i + 1) as u32, None);
            proofs.insert(element.to_field(), (leaves[i], merkle_path, sig));
            indices.push((i + 1) as u32);
            prover_set.push(element);
        }

        let (steps, proof_opt) = AlbaProof::prove_routine(set_size, &params, &prover_set);
        let proof = proof_opt.unwrap();
        assert!(proof.verify(set_size, params));

        let alba_meta_data = AlbaProofMeta::new(proof.retry_counter, proof.search_counter);
        let mut wits = vec![];
        for element in proof.element_sequence {
            let (merkle_leaf, merkle_path, sig) = proofs.get(&element.to_field()).unwrap();
            let wit = (
                *merkle_leaf,
                merkle_path.clone(),
                sig.clone(),
                element.data.clone(),
            );
            wits.push(wit);
        }

        let instance = (merkle_root, msg);
        let witness = (wits, alba_meta_data);

        (instance, witness)
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
    fn test_alba_certificate() {
        const K: u32 = 18;
        // let srs = filecoin_srs(K);
        let srs = open(K);

        let num_signers: usize = 3000;
        let merkle_tree_depth = num_signers.next_power_of_two().trailing_zeros();
        let quorum = 614;
        let num_lotteries = 8148;

        let proof_size = 55;
        let search_width = 4374;
        let max_retries = 32;
        let set_size = 614;
        let valid_proof_probability = 0.001136217032367627;
        let dfs_bound = 788581;
        let alba_proof_params = AlbaProofParams::new(
            proof_size,
            max_retries,
            search_width,
            valid_proof_probability,
            dfs_bound,
        );
        // valid_proof_target = 2^128 * 0.001136217032367627
        let alba_params = AlbaParams {
            proof_size,
            search_width,
            max_retries,
            set_size,
            valid_proof_target: alba_proof_params.valid_proof_target,
        };
        let relation = Certificate::new(alba_params, num_lotteries, merkle_tree_depth);
        println!("Circuit {:?}", relation);

        let (instance, witness) = create_proofs(num_signers, set_size, &alba_proof_params);

        {
            let circuit = MidnightCircuit::from_relation(&relation);
            println!("min_k {:?}", circuit.min_k());
            let cost = CircuitCost::<BlstG1, _>::measure(K, &circuit);
            println!("{:?}", cost);
        }

        let start = Instant::now();
        let vk = compact_std_lib::setup_vk(&srs, &relation);
        let pk = compact_std_lib::setup_pk(&relation, &vk);
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("\nvk pk generation took: {:?}", duration);

        {
            let mut buffer = Cursor::new(Vec::new());
            // Serialize the MidnightVK instance to the buffer in the RawBytes format
            vk.write(&mut buffer, SerdeFormat::RawBytes).unwrap();
            // Get the size of the serialized MidnightVK
            println!("vk length {:?}", buffer.get_ref().len());
        }

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
                None,
                &proof
            )
            .is_ok()
        );
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("\nProof verification took: {:?}", duration);
    }
}
