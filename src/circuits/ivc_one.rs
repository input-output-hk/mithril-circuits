use crate::{
    Accumulator, ArithInstructions, AssertionInstructions, AssignedAccumulator,
    AssignedForeignPoint, AssignedNative, AssignedNativePoint, AssignedScalarOfNativeCurve,
    AssignedVk, AssignmentInstructions, BinaryInstructions, BlstrsEmulation, Circuit, CircuitCurve,
    ComposableChip, ConstraintSystem, ControlFlowInstructions, ConversionInstructions,
    DST_SCHNORR_SIGNATURE, EccChip, EccConfig, EccInstructions, EqualityInstructions, Error,
    EvaluationDomain, FieldChip, ForeignEccChip, ForeignEccConfig, HashInstructions, Jubjub,
    Layouter, NB_ARITH_COLS, NB_ARITH_FIXED_COLS, NB_EDWARDS_COLS, NB_POSEIDON_ADVICE_COLS,
    NB_POSEIDON_FIXED_COLS, NativeChip, NativeConfig, NativeGadget, P2RDecompositionChip,
    P2RDecompositionConfig, PoseidonChip, PoseidonConfig, Pow2RangeChip, PublicInputInstructions,
    SelfEmulation, SimpleFloorPlanner, Value, VerifierGadget, ZeroInstructions,
    nb_foreign_ecc_chip_columns,
    schnorr_signature::{Signature as SchnorrSignature, VerificationKey as SchnorrVerificationKey},
    verifier,
};

use crate::circuits::{CERT_VK_NAME, IVC_SD_NAME};
use ff::Field;
use halo2curves::group::Group;
use midnight_circuits::hash::sha256::{
    NB_SHA256_ADVICE_COLS, NB_SHA256_FIXED_COLS, Sha256Chip, Sha256Config,
};
use std::collections::HashSet;

type S = BlstrsEmulation;
type F = <S as SelfEmulation>::F;
type C = <S as SelfEmulation>::C;

type E = <S as SelfEmulation>::Engine;
type CBase = <C as CircuitCurve>::Base;

type NG = NativeGadget<F, P2RDecompositionChip<F>, NativeChip<F>>;

#[cfg(feature = "truncated-challenges")]
const K: u32 = 19;

#[cfg(not(feature = "truncated-challenges"))]
const K: u32 = 19;

pub const PREIMAGE_SIZE: usize = 190;

#[derive(Debug, Clone)]
pub struct IvcConfig {
    native_config: NativeConfig,
    core_decomp_config: P2RDecompositionConfig,
    jubjub_config: EccConfig,
    foreign_ecc_config: ForeignEccConfig<C>,
    poseidon_config: PoseidonConfig<F>,
    sha256_config: Sha256Config,
}

#[derive(Clone, Debug)]
pub struct IvcCircuit {
    pub self_vk: (EvaluationDomain<F>, ConstraintSystem<F>, Value<F>), // (domain, cs, vk_repr)
    pub prev_state: Value<F>,
    pub prev_msg: Value<F>,
    pub prev_merkle_root: Value<F>,
    pub prev_next_merkle_root: Value<F>,
    pub prev_current_epoch: Value<F>,
    pub prev_proof: Value<Vec<u8>>,
    pub prev_acc: Value<Accumulator<S>>,
    // Genesis certificate
    pub genesis_vk: Value<SchnorrVerificationKey>,
    pub genesis_msg: Value<F>,
    pub genesis_sig: Value<SchnorrSignature>,
    // Inner certificate circuit
    pub cert_vk: (EvaluationDomain<F>, ConstraintSystem<F>, Value<F>), // (domain, cs, vk_repr)
    pub cert_merkle_root: Value<F>,
    pub cert_msg: Value<F>,
    pub cert_proof: Value<Vec<u8>>,
    // Protocol msg preimage bytes
    pub msg_preimage: Value<[u8; PREIMAGE_SIZE]>,
}

pub fn configure_ivc_circuit(meta: &mut ConstraintSystem<F>) -> IvcConfig {
    let nb_advice_cols = [
        NB_EDWARDS_COLS,
        NB_POSEIDON_ADVICE_COLS,
        NB_SHA256_ADVICE_COLS,
        nb_foreign_ecc_chip_columns::<F, C, C, NG>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);

    let nb_fixed_cols = [
        NB_ARITH_FIXED_COLS,
        NB_POSEIDON_FIXED_COLS,
        NB_SHA256_FIXED_COLS,
    ]
    .into_iter()
    .max()
    .unwrap_or(0);

    let advice_columns: Vec<_> = (0..nb_advice_cols).map(|_| meta.advice_column()).collect();
    let fixed_columns: Vec<_> = (0..nb_fixed_cols).map(|_| meta.fixed_column()).collect();
    let committed_instance_column = meta.instance_column();
    let instance_column = meta.instance_column();

    let native_config = NativeChip::configure(
        meta,
        &(
            advice_columns[..NB_ARITH_COLS].try_into().unwrap(),
            fixed_columns[..NB_ARITH_FIXED_COLS].try_into().unwrap(),
            [committed_instance_column, instance_column],
        ),
    );
    let core_decomp_config = {
        let pow2_config = Pow2RangeChip::configure(meta, &advice_columns[1..NB_ARITH_COLS]);
        P2RDecompositionChip::configure(meta, &(native_config.clone(), pow2_config))
    };

    let jubjub_config =
        EccChip::<Jubjub>::configure(meta, &advice_columns[..NB_EDWARDS_COLS].try_into().unwrap());

    let base_config = FieldChip::<F, CBase, C, NG>::configure(meta, &advice_columns);
    let foreign_ecc_config =
        ForeignEccChip::<F, C, C, NG, NG>::configure(meta, &base_config, &advice_columns);

    let poseidon_config = PoseidonChip::configure(
        meta,
        &(
            advice_columns[..NB_POSEIDON_ADVICE_COLS]
                .try_into()
                .unwrap(),
            fixed_columns[..NB_POSEIDON_FIXED_COLS].try_into().unwrap(),
        ),
    );

    let sha256_config = Sha256Chip::configure(
        meta,
        &(
            advice_columns[..NB_SHA256_ADVICE_COLS].try_into().unwrap(),
            fixed_columns[..NB_SHA256_FIXED_COLS].try_into().unwrap(),
        ),
    );

    IvcConfig {
        native_config,
        core_decomp_config,
        jubjub_config,
        foreign_ecc_config,
        poseidon_config,
        sha256_config,
    }
}

impl Circuit<F> for IvcCircuit {
    type Config = IvcConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unreachable!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        configure_ivc_circuit(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let native_chip = <NativeChip<F> as ComposableChip<F>>::new(&config.native_config, &());
        let core_decomp_chip =
            P2RDecompositionChip::new(&config.core_decomp_config, &(K as usize - 1));
        let native_gadget = NativeGadget::new(core_decomp_chip.clone(), native_chip.clone());
        let jubjub_chip = EccChip::<Jubjub>::new(&config.jubjub_config, &native_gadget);
        let foreign_ecc_chip: ForeignEccChip<_, C, C, _, _> =
            { ForeignEccChip::new(&config.foreign_ecc_config, &native_gadget, &native_gadget) };
        let poseidon_chip = PoseidonChip::new(&config.poseidon_config, &native_chip);
        let sha256_chip = Sha256Chip::new(&config.sha256_config, &native_gadget);
        let verifier_chip: VerifierGadget<S> =
            VerifierGadget::new(&foreign_ecc_chip, &native_gadget, &poseidon_chip);

        let id_point: AssignedForeignPoint<_, _, _> =
            foreign_ecc_chip.assign_fixed(&mut layouter, C::identity())?;

        let [
            prev_state,
            prev_msg,
            prev_merkle_root,
            prev_next_merkle_root,
            prev_current_epoch,
            cert_merkle_root,
            cert_msg,
        ]: [AssignedNative<_>; 7] = native_gadget
            .assign_many(
                &mut layouter,
                &[
                    self.prev_state,
                    self.prev_msg,
                    self.prev_merkle_root,
                    self.prev_next_merkle_root,
                    self.prev_current_epoch,
                    self.cert_merkle_root,
                    self.cert_msg,
                ],
            )?
            .try_into()
            // this won't fail
            .unwrap();

        // Assign and verify genesis certificate
        let genesis_msg: AssignedNative<_> =
            native_gadget.assign_as_public_input(&mut layouter, self.genesis_msg)?;
        let genesis_vk: AssignedNativePoint<_> =
            jubjub_chip.assign_as_public_input(&mut layouter, self.genesis_vk.map(|vk| vk.0))?;
        let is_genesis_sig_valid = {
            let s: AssignedScalarOfNativeCurve<_> =
                jubjub_chip.assign(&mut layouter, self.genesis_sig.clone().map(|sig| sig.s))?;
            let c_native: AssignedNative<_> =
                native_gadget.assign(&mut layouter, self.genesis_sig.clone().map(|sig| sig.c))?;
            let c: AssignedScalarOfNativeCurve<_> =
                jubjub_chip.convert(&mut layouter, &c_native)?;

            let dst_signature: AssignedNative<_> =
                native_gadget.assign_fixed(&mut layouter, DST_SCHNORR_SIGNATURE)?;
            let generator: AssignedNativePoint<_> = jubjub_chip.assign_fixed(
                &mut layouter,
                <Jubjub as CircuitCurve>::CryptographicGroup::generator(),
            )?;

            let cap_r = jubjub_chip.msm(
                &mut layouter,
                &[s.clone(), c.clone()],
                &[generator.clone(), genesis_vk.clone()],
            )?;

            let vk_x = jubjub_chip.x_coordinate(&genesis_vk);
            let vk_y = jubjub_chip.y_coordinate(&genesis_vk);
            let cap_r_x = jubjub_chip.x_coordinate(&cap_r);
            let cap_r_y = jubjub_chip.y_coordinate(&cap_r);

            let c_prime = poseidon_chip.hash(
                &mut layouter,
                &[
                    dst_signature.clone(),
                    vk_x,
                    vk_y,
                    cap_r_x,
                    cap_r_y,
                    genesis_msg.clone(),
                ],
            )?;

            native_gadget.is_equal(&mut layouter, &c_prime, &c_native)?
        };

        let is_genesis = native_gadget.is_zero(&mut layouter, &prev_state)?;
        let is_not_genesis = native_gadget.not(&mut layouter, &is_genesis)?;

        {
            // Skip the genesis signature verification if it is not genesis
            let check_genesis = native_gadget.or(
                &mut layouter,
                &[is_genesis_sig_valid, is_not_genesis.clone()],
            )?;
            native_gadget.assert_equal_to_fixed(&mut layouter, &check_genesis, true)?;

            // Update state
            let next_state = native_gadget.add_constant(&mut layouter, &prev_state, F::ONE)?;
            native_gadget.constrain_as_public_input(&mut layouter, &next_state)?;
        }

        {
            // Open msg hash to check the link between certificates
            // If it is genesis, select genesis msg as msg; otherwise, select cert msg as msg.
            let msg = native_gadget.select(&mut layouter, &is_genesis, &genesis_msg, &cert_msg)?;
            native_gadget.constrain_as_public_input(&mut layouter, &msg)?;

            let preimage = self.msg_preimage.transpose_array();
            let assigned_preimage = native_gadget.assign_many(&mut layouter, &preimage)?;
            let hash = sha256_chip.hash(&mut layouter, &assigned_preimage)?;

            let factor = F::from(256u64);
            let bases: Vec<_> = (0..32)
                .scan(F::ONE, |s, _| {
                    let out = *s;
                    *s *= factor;
                    Some(out)
                })
                .collect();

            {
                // Compare msg and hash
                let mut items = vec![];
                for (v, base) in hash.into_iter().zip(bases.iter()) {
                    items.push((*base, v.into()));
                }
                let hash_native =
                    native_gadget.linear_combination(&mut layouter, &items, F::ZERO)?;
                native_gadget.assert_equal(&mut layouter, &msg, &hash_native)?;
            }

            // If it is genesis, merkle_root = 0; otherwise, merkle_root = cert_merkle_root.
            let zero = native_gadget.assign_fixed(&mut layouter, F::ZERO)?;
            let merkle_root =
                native_gadget.select(&mut layouter, &is_genesis, &zero, &cert_merkle_root)?;
            native_gadget.constrain_as_public_input(&mut layouter, &merkle_root)?;

            // Read the value of next merkle root and current epoch
            // digest(6) | bytes(32) | next_aggregate_verification_key(31) | bytes(44) | next_protocol_parameters(24) | bytes(32) | current_epoch(13) | bytes(8)
            // todo: check field keywords(?)
            // todo: extract next protocol parameters
            let next_merkle_root_bytes = assigned_preimage[69..101].to_vec();
            let current_epoch_bytes = assigned_preimage[182..190].to_vec();

            {
                // Constraint the next merkle root as public input
                let mut items = vec![];
                for (v, base) in next_merkle_root_bytes.into_iter().zip(bases.iter()) {
                    items.push((*base, v.into()));
                }
                let next_merkle_root =
                    native_gadget.linear_combination(&mut layouter, &items, F::ZERO)?;
                native_gadget.constrain_as_public_input(&mut layouter, &next_merkle_root)?;
            }

            let (is_same_epoch, is_next_epoch) = {
                // Constraint the current epoch as public input
                let mut items = vec![];
                for (v, base) in current_epoch_bytes.into_iter().zip(bases.iter()) {
                    items.push((*base, v.into()));
                }
                let current_epoch =
                    native_gadget.linear_combination(&mut layouter, &items, F::ZERO)?;
                native_gadget.constrain_as_public_input(&mut layouter, &current_epoch)?;

                // current_epoch == prev_current_epoch
                let is_same_epoch =
                    native_gadget.is_equal(&mut layouter, &current_epoch, &prev_current_epoch)?;

                //  current_epoch = prev_current_epoch + 1
                let next =
                    native_gadget.add_constant(&mut layouter, &prev_current_epoch, F::ONE)?;
                let is_next_epoch = native_gadget.is_equal(&mut layouter, &current_epoch, &next)?;

                {
                    // If prev_state == 1, the previous certificate is a genesis certificate and
                    // the current certificate is the first certificate after the genesis and
                    // its epoch number must be the next epoch number.
                    let is_first =
                        native_gadget.is_equal_to_fixed(&mut layouter, &prev_state, F::ONE)?;
                    let is_not_first = native_gadget.not(&mut layouter, &is_first)?;

                    let mut is_valid =
                        native_gadget.and(&mut layouter, &[is_first, is_next_epoch.clone()])?;
                    is_valid = native_gadget.or(&mut layouter, &[is_not_first, is_valid])?;
                    native_gadget.assert_equal_to_fixed(&mut layouter, &is_valid, true)?;
                }

                (is_same_epoch, is_next_epoch)
            };

            {
                // Check the link on merkle root; if it is genesis, skip the checking
                let mut is_equal_current =
                    native_gadget.is_equal(&mut layouter, &merkle_root, &prev_merkle_root)?;
                is_equal_current =
                    native_gadget.and(&mut layouter, &[is_equal_current, is_same_epoch])?;

                let mut is_equal_next =
                    native_gadget.is_equal(&mut layouter, &merkle_root, &prev_next_merkle_root)?;
                is_equal_next =
                    native_gadget.and(&mut layouter, &[is_equal_next, is_next_epoch])?;

                let is_link_valid = native_gadget.or(
                    &mut layouter,
                    &[is_genesis, is_equal_current, is_equal_next],
                )?;
                native_gadget.assert_equal_to_fixed(&mut layouter, &is_link_valid, true)?;
            }
        }

        {
            // Assign for cert circuit proof verification
            let (cert_domain, cert_cs, cert_vk_value) = &self.cert_vk;
            let assigned_cert_vk: AssignedVk<S> = verifier_chip.assign_vk_as_public_input(
                &mut layouter,
                CERT_VK_NAME,
                cert_domain,
                cert_cs,
                *cert_vk_value,
            )?;

            let mut cert_proof_acc = verifier_chip.prepare(
                &mut layouter,
                &assigned_cert_vk,
                &[("com_instance", id_point.clone())],
                &[&[cert_merkle_root.clone(), cert_msg.clone()]],
                self.cert_proof.clone(),
            )?;

            // If `prev_state` is genesis, we allow the prover to change the (probably
            // invalid) accumulator by a default accumulator that satisfies the invariant.
            AssignedAccumulator::scale_by_bit(
                &mut layouter,
                &native_gadget,
                &is_not_genesis,
                &mut cert_proof_acc,
            )?;
            cert_proof_acc.collapse(&mut layouter, &foreign_ecc_chip, &native_gadget)?;

            // Assign for self-proof verification
            let (self_domain, self_cs, self_vk_value) = &self.self_vk;
            let assigned_self_vk: AssignedVk<S> = verifier_chip.assign_vk_as_public_input(
                &mut layouter,
                IVC_SD_NAME,
                self_domain,
                self_cs,
                *self_vk_value,
            )?;

            // Update accumulator
            // Witness a proof and an accumulator that ensure the validity of `prev_state`.
            let prev_acc = {
                let mut fixed_base_names = vec![String::from("com_instance")];
                fixed_base_names.extend(verifier::fixed_base_names::<S>(
                    IVC_SD_NAME,
                    self_cs.num_fixed_columns() + self_cs.num_selectors(),
                    self_cs.permutation().columns.len(),
                ));
                fixed_base_names.extend(verifier::fixed_base_names::<S>(
                    CERT_VK_NAME,
                    cert_cs.num_fixed_columns() + cert_cs.num_selectors(),
                    cert_cs.permutation().columns.len(),
                ));
                // Remove repeated names
                let mut seen = HashSet::new();
                fixed_base_names.retain(|x| seen.insert(x.clone()));
                AssignedAccumulator::assign(
                    &mut layouter,
                    &foreign_ecc_chip,
                    &native_gadget,
                    1,
                    1,
                    &[],
                    &fixed_base_names,
                    self.prev_acc.clone(),
                )?
            };

            // Public inputs for this IVC circuit:
            // [genesis_msg, genesis_vk, prev_state, prev_msg, prev_next_merkle_root, prev_current_epoch, cert_vk, self_vk, prev_acc]
            let assigned_pi = [
                vec![
                    genesis_msg.clone(),
                    jubjub_chip.x_coordinate(&genesis_vk),
                    jubjub_chip.y_coordinate(&genesis_vk),
                ],
                vec![
                    prev_state,
                    prev_msg,
                    prev_merkle_root,
                    prev_next_merkle_root,
                    prev_current_epoch,
                ],
                verifier_chip.as_public_input(&mut layouter, &assigned_cert_vk)?,
                verifier_chip.as_public_input(&mut layouter, &assigned_self_vk)?,
                verifier_chip.as_public_input(&mut layouter, &prev_acc)?,
            ]
            .concat();

            // Verify a witnessed proof that ensures the validity of `prev_state`.
            // The proof is valid iff `proof_acc` satisfies the invariant.
            let mut self_proof_acc = verifier_chip.prepare(
                &mut layouter,
                &assigned_self_vk,
                &[("com_instance", id_point)],
                &[&assigned_pi],
                self.prev_proof.clone(),
            )?;

            // If `prev_state` is genesis, we allow the prover to change the (probably
            // invalid) accumulator by a default accumulator that satisfies the invariant.
            AssignedAccumulator::scale_by_bit(
                &mut layouter,
                &native_gadget,
                &is_not_genesis,
                &mut self_proof_acc,
            )?;
            self_proof_acc.collapse(&mut layouter, &foreign_ecc_chip, &native_gadget)?;

            // Accumulate the cert_proof_acc
            let mut acc = AssignedAccumulator::<S>::accumulate(
                &mut layouter,
                &verifier_chip,
                &native_gadget,
                &poseidon_chip,
                &[prev_acc, cert_proof_acc, self_proof_acc],
            )?;
            acc.collapse(&mut layouter, &foreign_ecc_chip, &native_gadget)?;

            verifier_chip.constrain_as_public_input(&mut layouter, &acc)?;
        }

        core_decomp_chip.load(&mut layouter)?;
        sha256_chip.load(&mut layouter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::*;
    use crate::merkle_tree::{MTLeaf, MerklePath, MerkleTree, MerkleTreeCommitment};
    use crate::protocol_message::{
        AggregateVerificationKey, ProtocolMessage, ProtocolMessagePartKey,
    };
    use crate::utils::jubjub_base_from_le_bytes;
    use crate::{
        AssignedNative, Bls12, CircuitTranscript, Instantiable, JubjubBase, KZGCommitmentScheme,
        MerkleRoot, Msg, Msm, ParamsKZG, PoseidonState, Transcript, create_proof, keygen_pk,
        keygen_vk_with_k, prepare,
        schnorr_signature::{
            Signature as SchnorrSignature, SigningKey as SchnorrSigningKey,
            VerificationKey as SchnorrVerificationKey,
        },
        unique_signature::{Signature, SigningKey, VerificationKey},
    };
    use crate::{Relation, certificate::Certificate};
    use ff::Field;
    use midnight_proofs::dev::cost_model::circuit_model;
    use midnight_proofs::utils::SerdeFormat;
    use midnight_zk_stdlib as zk;
    use rand_core::OsRng;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{BufReader, Cursor};
    use std::time::Instant;

    const NUM_CERT: usize = 3;
    fn open(k: u32) -> ParamsKZG<Bls12> {
        let path = format!("examples/assets/params_kzg_unsafe_{}", k);
        let file = File::open(path).unwrap();
        let mut reader = BufReader::new(file);
        let params: ParamsKZG<Bls12> =
            ParamsKZG::read_custom(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap();

        params
    }

    fn create_merkle_tree(n: usize) -> (Vec<SigningKey>, Vec<MTLeaf>, MerkleTree) {
        //  let mut rng = ChaCha20Rng::seed_from_u64(1234);
        let mut rng = OsRng;

        let mut sks = Vec::new();
        let mut leaves = Vec::new();
        for _ in 0..n {
            let sk = SigningKey::generate(&mut rng);
            let vk = VerificationKey::from(&sk); // Replace this with actual initialization if provided
            leaves.push(MTLeaf(vk, -F::ONE));
            sks.push(sk);
        }
        let tree = MerkleTree::create(&leaves);

        (sks, leaves, tree)
    }

    fn setup() -> (
        SchnorrVerificationKey,
        u64,
        SchnorrSignature,
        Certificate,
        Vec<Msg>,
        Vec<MerkleRoot>,
        Vec<MerkleRoot>,
        Vec<Vec<u8>>,
        Vec<Vec<(MTLeaf, MerklePath, Signature, u32)>>,
        Vec<Vec<F>>,
    ) {
        //  let mut rng = ChaCha20Rng::seed_from_u64(1234);
        let mut rng = OsRng;
        let num_signers: usize = 3000;
        let depth = num_signers.next_power_of_two().trailing_zeros();
        let quorum = 3;
        let num_lotteries = quorum * 10;
        let total_stake = 1000000u64;

        let relation = Certificate::new(quorum, num_lotteries, depth);
        println!("Circuit {:?}", relation);

        let (sks, leaves, merkle_tree) = create_merkle_tree(num_signers);
        let avk =
            AggregateVerificationKey::new(merkle_tree.to_merkle_tree_commitment(), total_stake);

        // Genesis certificate
        let genesis_sk = SchnorrSigningKey::generate(&mut rng);
        let genesis_vk = SchnorrVerificationKey::from(&genesis_sk);
        let genesis_epoch = 5u64;
        let genesis_next_merkle_root = merkle_tree.root();

        let (genesis_msg, genesis_preimage) = {
            let mut protocol_message = ProtocolMessage::new();
            protocol_message.set_message_part(ProtocolMessagePartKey::Digest, vec![2u8; 32]);
            protocol_message.set_message_part(
                ProtocolMessagePartKey::NextAggregateVerificationKey,
                avk.clone().into(),
            );
            protocol_message.set_message_part(
                ProtocolMessagePartKey::NextProtocolParameters,
                vec![0u8; 32],
            );
            protocol_message.set_message_part(
                ProtocolMessagePartKey::CurrentEpoch,
                genesis_epoch.to_le_bytes().into(),
            );
            let preimage = protocol_message.get_preimage();
            let msg = protocol_message.compute_hash();
            (jubjub_base_from_le_bytes(&msg), preimage)
        };
        let genesis_sig = genesis_sk.sign(&[genesis_msg], &mut rng);
        genesis_sig.verify(&[genesis_msg], &genesis_vk).unwrap();

        let mut msgs = vec![genesis_msg];
        let mut preimages = vec![genesis_preimage];
        let mut witnesses = vec![vec![]];
        let mut merkle_roots = vec![F::ZERO];
        let mut next_merkle_roots = vec![genesis_next_merkle_root];
        let mut instances = vec![vec![]];

        let mut current_epoch = genesis_epoch;
        let merkle_root = merkle_tree.root();
        for i in 1..NUM_CERT {
            current_epoch += 1;
            let (msg, preimage) = {
                let mut protocol_message = ProtocolMessage::new();
                protocol_message.set_message_part(ProtocolMessagePartKey::Digest, vec![3u8; 32]);
                protocol_message.set_message_part(
                    ProtocolMessagePartKey::NextAggregateVerificationKey,
                    avk.clone().into(),
                );
                protocol_message.set_message_part(
                    ProtocolMessagePartKey::NextProtocolParameters,
                    vec![0u8; 32],
                );
                protocol_message.set_message_part(
                    ProtocolMessagePartKey::CurrentEpoch,
                    current_epoch.to_le_bytes().into(),
                );
                let preimage = protocol_message.get_preimage();
                let msg = protocol_message.compute_hash();
                (jubjub_base_from_le_bytes(&msg), preimage)
            };

            let mut witness = vec![];
            for j in 0..quorum as usize {
                let usk = sks[j].clone();
                let uvk = leaves[j].0;
                let sig = usk.sign(&[merkle_root, msg], &mut OsRng);
                sig.verify(&[merkle_root, msg], &uvk).unwrap();

                let merkle_path = merkle_tree.get_path(j);
                let computed_root = merkle_path.compute_root(leaves[j]);
                assert_eq!(merkle_root, computed_root);

                // Any index is eligible as target is set to be the maximum
                witness.push((leaves[j], merkle_path, sig, (j + 1) as u32));
            }

            let instance = Certificate::format_instance(&(merkle_root, msg)).unwrap();

            msgs.push(msg);
            preimages.push(preimage);
            witnesses.push(witness);
            merkle_roots.push(merkle_root);
            next_merkle_roots.push(merkle_root);
            instances.push(instance);
        }

        (
            genesis_vk,
            genesis_epoch,
            genesis_sig,
            relation,
            msgs,
            merkle_roots,
            next_merkle_roots,
            preimages,
            witnesses,
            instances,
        )
    }

    macro_rules! prove_ivc {
        ($TranscriptType:ty, $circuit:expr, $srs:expr, $pk:expr, $public_inputs:expr) => {{
            // Initialize the transcript
            let mut transcript = CircuitTranscript::<$TranscriptType>::init();

            // Call create_proof
            let res = create_proof::<
                F,
                KZGCommitmentScheme<E>,
                CircuitTranscript<$TranscriptType>,
                IvcCircuit,
            >(
                $srs,
                $pk,
                &[$circuit.clone()],
                1,
                &[&[&[], $public_inputs]],
                OsRng,
                &mut transcript,
            );

            // Handle error
            res.unwrap_or_else(|e| panic!("create proof error {:?}", e));

            // Finalize transcript and return proof bytes
            transcript.finalize()
        }};
    }

    macro_rules! verify_prepare {
        ($TranscriptType:ty, $proof:expr, $vk:expr, $public_inputs:expr) => {{
            // Start a transcript from proof bytes
            let mut transcript = CircuitTranscript::<$TranscriptType>::init_from_bytes($proof);

            // Run prepare
            let dual_msm =
                prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<$TranscriptType>>(
                    $vk,
                    &[&[C::identity()]],
                    &[&[$public_inputs]],
                    &mut transcript,
                )
                .expect("Verification failed");
            dual_msm
        }};
    }

    #[test]
    fn test_ivc_one() {
        let srs = open(K);

        // Create genesis certificate
        let (
            genesis_vk,
            genesis_epoch,
            genesis_sig,
            cert_relation,
            msgs,
            merkle_roots,
            next_merkle_roots,
            preimages,
            witnesses,
            instances,
        ) = setup();

        // Set up cert circuit
        println!("setting up cert circuit...");
        const K_INNER: u32 = 13;
        let mut cert_srs = srs.clone();
        cert_srs.downsize(K_INNER);

        let start = Instant::now();
        let cert_vk = zk::setup_vk(&cert_srs, &cert_relation);
        let cert_pk = zk::setup_pk(&cert_relation, &cert_vk);
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("cert circuit vk pk generation took: {:?}", duration);

        let mut cert_fixed_bases = BTreeMap::new();
        cert_fixed_bases.insert(String::from("com_instance"), C::identity());
        cert_fixed_bases.extend(verifier::fixed_bases::<S>(CERT_VK_NAME, &cert_vk.vk()));
        let cert_fixed_base_names = cert_fixed_bases.keys().cloned().collect::<Vec<_>>();

        let cert_trivial_acc = Accumulator::<S>::new(
            Msm::new(&[C::default()], &[F::ONE], &BTreeMap::new()),
            Msm::new(
                &[C::default()],
                &[F::ONE],
                &cert_fixed_base_names
                    .iter()
                    .map(|name| (name.clone(), F::ZERO))
                    .collect(),
            ),
        );

        let mut cert_proofs = vec![vec![]];
        // We don't need to use cert_trivial_acc
        let mut cert_accs = vec![cert_trivial_acc];
        for i in 1..NUM_CERT {
            let start = Instant::now();
            let cert_proof = zk::prove::<Certificate, PoseidonState<F>>(
                &cert_srs,
                &cert_pk,
                &cert_relation,
                &(merkle_roots[i], msgs[i]),
                witnesses[i].clone(),
                OsRng,
            )
            .expect("Proof generation should not fail");
            let duration = start.elapsed(); // Measure the elapsed time after proof generation.
            println!("Inner circuit proof generation took: {:?}", duration);

            let cert_dual_msm =
                verify_prepare!(PoseidonState<F>, &cert_proof, cert_vk.vk(), &instances[i]);
            assert!(cert_dual_msm.clone().check(&cert_srs.verifier_params()));

            let mut cert_acc: Accumulator<S> = cert_dual_msm.into();
            cert_acc.extract_fixed_bases(&cert_fixed_bases);
            assert!(cert_acc.check(&cert_srs.s_g2().into(), &cert_fixed_bases));
            cert_acc.collapse();

            cert_proofs.push(cert_proof);
            cert_accs.push(cert_acc);
        }

        // ivc circuit with cert vk
        let mut self_cs = ConstraintSystem::default();
        configure_ivc_circuit(&mut self_cs);
        let self_domain = EvaluationDomain::new(self_cs.degree() as u32, K);

        let default_ivc_circuit = IvcCircuit {
            self_vk: (self_domain.clone(), self_cs.clone(), Value::unknown()),
            prev_state: Value::known(F::ZERO),
            prev_msg: Value::unknown(),
            prev_merkle_root: Value::unknown(),
            prev_next_merkle_root: Value::unknown(),
            prev_current_epoch: Value::unknown(),
            prev_proof: Value::unknown(),
            prev_acc: Value::unknown(),
            genesis_vk: Value::known(genesis_vk),
            genesis_msg: Value::known(msgs[0]),
            genesis_sig: Value::known(genesis_sig.clone()),
            cert_vk: (
                cert_vk.vk().get_domain().clone(),
                cert_vk.vk().cs().clone(),
                Value::known(cert_vk.vk().transcript_repr()),
            ),
            cert_merkle_root: Value::unknown(),
            cert_proof: Value::unknown(),
            cert_msg: Value::unknown(),
            msg_preimage: Value::known(preimages[0].clone().try_into().unwrap()),
        };

        {
            let circuit_model = circuit_model::<_, 48, 32>(&default_ivc_circuit);
            println!("{:?}", circuit_model);
        }

        let start = Instant::now();
        let self_vk = keygen_vk_with_k(&srs, &default_ivc_circuit, K).unwrap();
        let self_pk = keygen_pk(self_vk.clone(), &default_ivc_circuit).unwrap();
        println!("Computed IVC circuit vk and pk in {:?} s", start.elapsed());

        {
            let mut buffer = Cursor::new(Vec::new());
            // Serialize the MidnightVK instance to the buffer in the RawBytes format
            self_vk.write(&mut buffer, SerdeFormat::RawBytes).unwrap();
            // Get the size of the serialized MidnightVK
            println!("ivc_with_cert vk length {:?}", buffer.get_ref().len());
        }

        let mut self_fixed_bases = BTreeMap::new();
        self_fixed_bases.insert(String::from("com_instance"), C::identity());
        self_fixed_bases.extend(verifier::fixed_bases::<S>(IVC_SD_NAME, &self_vk));
        let self_fixed_base_names = self_fixed_bases.keys().cloned().collect::<Vec<_>>();
        println!(
            "IVC fixed base name length {:?}",
            self_fixed_base_names.len()
        );

        let mut combined_fixed_bases = BTreeMap::new();
        combined_fixed_bases.extend(cert_fixed_bases.clone());
        combined_fixed_bases.extend(self_fixed_bases.clone());
        let combined_fixed_base_names = combined_fixed_bases.keys().cloned().collect::<Vec<_>>();
        println!(
            "Combined fixed base name length {:?}",
            combined_fixed_base_names.len()
        );

        let trivial_acc = Accumulator::<S>::new(
            Msm::new(&[C::default()], &[F::ONE], &BTreeMap::new()),
            Msm::new(
                &[C::default()],
                &[F::ONE],
                &combined_fixed_base_names
                    .iter()
                    .map(|name| (name.clone(), F::ZERO))
                    .collect(),
            ),
        );

        // Set the previous values
        let mut prev_state = F::ZERO;
        let mut prev_msg = F::ZERO;
        let mut prev_merkle_root = F::ZERO;
        let mut prev_next_merkle_root = F::ZERO;
        let mut prev_current_epoch = F::ZERO;
        let mut prev_proof: Vec<u8> = vec![];
        let mut prev_acc = trivial_acc.clone();

        let mut state = prev_state + F::ONE;
        let mut current_epoch = F::from(genesis_epoch);
        let mut acc = prev_acc.clone();
        for i in 0..NUM_CERT {
            let circuit = IvcCircuit {
                self_vk: (
                    self_domain.clone(),
                    self_cs.clone(),
                    Value::known(self_vk.transcript_repr()),
                ),
                prev_state: Value::known(prev_state),
                prev_msg: Value::known(prev_msg),
                prev_merkle_root: Value::known(prev_merkle_root),
                prev_next_merkle_root: Value::known(prev_next_merkle_root),
                prev_current_epoch: Value::known(prev_current_epoch),
                prev_proof: Value::known(prev_proof.clone()),
                prev_acc: Value::known(prev_acc.clone()),
                genesis_vk: Value::known(genesis_vk),
                genesis_msg: Value::known(msgs[0]),
                genesis_sig: Value::known(genesis_sig.clone()),
                cert_vk: (
                    cert_vk.vk().get_domain().clone(),
                    cert_vk.vk().cs().clone(),
                    Value::known(cert_vk.vk().transcript_repr()),
                ),
                cert_merkle_root: Value::known(merkle_roots[i]),
                cert_msg: Value::known(msgs[i]),
                cert_proof: Value::known(cert_proofs[i].clone()),
                msg_preimage: Value::known(preimages[i].clone().try_into().unwrap()),
            };

            // Set public inputs [genesis_msg, genesis_vk, state, cert_msg, merkle_root, next_merkle_root, current_epoch, cert_vk, self_vk, acc]
            let public_inputs = [
                AssignedNative::<F>::as_public_input(&msgs[0]),
                AssignedNativePoint::<Jubjub>::as_public_input(&genesis_vk.0),
                AssignedNative::<F>::as_public_input(&state),
                AssignedNative::<F>::as_public_input(&msgs[i]),
                AssignedNative::<F>::as_public_input(&merkle_roots[i]),
                AssignedNative::<F>::as_public_input(&next_merkle_roots[i]),
                AssignedNative::<F>::as_public_input(&current_epoch),
                AssignedVk::<S>::as_public_input(&cert_vk.vk()),
                AssignedVk::<S>::as_public_input(&self_vk),
                AssignedAccumulator::as_public_input(&acc),
            ]
            .concat();
            println!("instance length {:?}", public_inputs.len());

            let start = Instant::now();
            let proof = {
                if i < NUM_CERT - 1 {
                    prove_ivc!(PoseidonState<F>, circuit, &srs, &self_pk, &public_inputs)
                } else {
                    // Generate the last proof using blake2 for transcript hash
                    prove_ivc!(blake2b_simd::State, circuit, &srs, &self_pk, &public_inputs)
                }
            };
            println!("\n{i}-th IVC proof created in {:?}", start.elapsed());
            println!("IVC proof size {:?}", proof.len());

            let proof_acc: Accumulator<S> = {
                let start = Instant::now();
                let dual_msm = if i < NUM_CERT - 1 {
                    verify_prepare!(PoseidonState<F>, &proof, &self_vk, &public_inputs)
                } else {
                    verify_prepare!(blake2b_simd::State, &proof, &self_vk, &public_inputs)
                };
                assert!(dual_msm.clone().check(&srs.verifier_params()));
                let duration = start.elapsed(); // Measure the elapsed time after proof generation.
                println!("IVC proof verification took: {:?}", duration);

                let mut proof_acc: Accumulator<S> = dual_msm.into();
                proof_acc.extract_fixed_bases(&self_fixed_bases);
                proof_acc.collapse();
                proof_acc
            };

            // Prepare the witnesses of the next iteration.
            prev_state = state;
            prev_msg = msgs[i];
            prev_merkle_root = merkle_roots[i];
            prev_next_merkle_root = next_merkle_roots[i];
            prev_current_epoch = current_epoch;
            prev_proof = proof;
            prev_acc = acc.clone();

            if i < NUM_CERT - 1 {
                // Prepare the next accumulator
                let mut accumulated = Accumulator::accumulate(&[
                    prev_acc.clone(),
                    cert_accs[i + 1].clone(),
                    proof_acc,
                ]);
                accumulated.collapse();

                assert!(
                    accumulated.check(&srs.s_g2().into(), &combined_fixed_bases),
                    "IVC acc verification failed"
                );

                acc = accumulated;
                // Set the new goals (public inputs) for the next iteration.
                state += F::ONE;
                current_epoch += F::ONE;
            }
        }

        {
            // Benchmark verifying ivc proof and accumulator together
            let start = Instant::now();
            let total = 100;
            for _ in 0..total {
                let public_inputs = [
                    AssignedNative::<F>::as_public_input(&msgs[0]),
                    AssignedNativePoint::<Jubjub>::as_public_input(&genesis_vk.0),
                    AssignedNative::<F>::as_public_input(&prev_state),
                    AssignedNative::<F>::as_public_input(&prev_msg),
                    AssignedNative::<F>::as_public_input(&prev_merkle_root),
                    AssignedNative::<F>::as_public_input(&prev_next_merkle_root),
                    AssignedNative::<F>::as_public_input(&prev_current_epoch),
                    AssignedVk::<S>::as_public_input(&cert_vk.vk()),
                    AssignedVk::<S>::as_public_input(&self_vk),
                    AssignedAccumulator::as_public_input(&prev_acc),
                ]
                .concat();

                // todo: combine the pair checking
                let dual_msm =
                    verify_prepare!(blake2b_simd::State, &prev_proof, &self_vk, &public_inputs);
                assert!(dual_msm.clone().check(&srs.verifier_params()));
                assert!(
                    prev_acc.check(&srs.s_g2().into(), &combined_fixed_bases),
                    "IVC acc verification failed"
                );
            }
            let duration = start.elapsed(); // Measure the elapsed time for proof verification.
            println!(
                "\nIVC and accumulator proof verification took: {:?}",
                duration / total
            );
        }
    }
}
