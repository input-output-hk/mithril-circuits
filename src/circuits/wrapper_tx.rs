use crate::{
    Accumulator, ArithInstructions, AssertionInstructions, AssignedAccumulator,
    AssignedForeignPoint, AssignedNative, AssignedVk, AssignmentInstructions, BinaryInstructions,
    BlstrsEmulation, Circuit, CircuitCurve, ComposableChip, ConstraintSystem, EqualityInstructions,
    Error, EvaluationDomain, FieldChip, ForeignEccChip, ForeignEccConfig, HashInstructions, Jubjub,
    Layouter, NB_ARITH_COLS, NB_ARITH_FIXED_COLS, NB_POSEIDON_ADVICE_COLS, NB_POSEIDON_FIXED_COLS,
    NativeChip, NativeConfig, NativeGadget, P2RDecompositionChip, P2RDecompositionConfig,
    PoseidonChip, PoseidonConfig, Pow2RangeChip, PublicInputInstructions, SelfEmulation,
    SimpleFloorPlanner, Value, VerifierGadget, nb_foreign_ecc_chip_columns,
    schnorr_signature::VerificationKey as SchnorrVerificationKey, verifier,
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

// cardano_transactions_merkle_root(32) | bytes(32) | next_aggregate_verification_key(31) | bytes(44) | next_protocol_parameters(24) | bytes(32) | current_epoch(13) | bytes(8) | latest_block_number(19) | bytes(8)
pub const PREIMAGE_SIZE: usize = 243;

#[derive(Debug, Clone)]
pub struct WrapperConfig {
    native_config: NativeConfig,
    core_decomp_config: P2RDecompositionConfig,
    foreign_ecc_config: ForeignEccConfig<C>,
    poseidon_config: PoseidonConfig<F>,
    sha256_config: Sha256Config,
}

#[derive(Clone, Debug)]
pub struct WrapperCircuit {
    // IVC stake distribution circuit
    pub ivc_vk: (EvaluationDomain<F>, ConstraintSystem<F>, Value<F>), // (domain, cs, vk_repr)
    pub ivc_state: Value<F>,
    pub ivc_msg: Value<F>,
    pub ivc_merkle_root: Value<F>,
    pub ivc_next_merkle_root: Value<F>,
    pub ivc_current_epoch: Value<F>,
    pub ivc_proof: Value<Vec<u8>>,
    pub ivc_acc: Value<Accumulator<S>>,
    // Genesis info
    pub genesis_vk: Value<SchnorrVerificationKey>,
    pub genesis_msg: Value<F>,
    // Tx certificate circuit
    pub cert_vk: (EvaluationDomain<F>, ConstraintSystem<F>, Value<F>), // (domain, cs, vk_repr)
    pub cert_merkle_root: Value<F>,
    pub cert_msg: Value<F>,
    pub cert_proof: Value<Vec<u8>>,
    // Protocol msg preimage bytes
    pub cert_msg_preimage: Value<[u8; PREIMAGE_SIZE]>,
}

pub fn configure_wrapper_circuit(meta: &mut ConstraintSystem<F>) -> WrapperConfig {
    let nb_advice_cols = [
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

    WrapperConfig {
        native_config,
        core_decomp_config,
        foreign_ecc_config,
        poseidon_config,
        sha256_config,
    }
}

impl Circuit<F> for WrapperCircuit {
    type Config = WrapperConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        unreachable!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        configure_wrapper_circuit(meta)
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
        let foreign_ecc_chip: ForeignEccChip<_, C, C, _, _> =
            { ForeignEccChip::new(&config.foreign_ecc_config, &native_gadget, &native_gadget) };
        let poseidon_chip = PoseidonChip::new(&config.poseidon_config, &native_chip);
        let sha256_chip = Sha256Chip::new(&config.sha256_config, &native_gadget);
        let verifier_chip: VerifierGadget<S> =
            VerifierGadget::new(&foreign_ecc_chip, &native_gadget, &poseidon_chip);

        let id_point: AssignedForeignPoint<_, _, _> =
            foreign_ecc_chip.assign_fixed(&mut layouter, C::identity())?;

        let [
            ivc_state,
            ivc_msg,
            ivc_merkle_root,
            ivc_next_merkle_root,
            ivc_current_epoch,
            cert_msg,
            cert_merkle_root,
        ]: [AssignedNative<_>; 7] = native_gadget
            .assign_many(
                &mut layouter,
                &[
                    self.ivc_state,
                    self.ivc_msg,
                    self.ivc_merkle_root,
                    self.ivc_next_merkle_root,
                    self.ivc_current_epoch,
                    self.cert_msg,
                    self.cert_merkle_root,
                ],
            )?
            .try_into()
            // this won't fail
            .unwrap();

        {
            native_gadget.constrain_as_public_input(&mut layouter, &cert_msg)?;
            native_gadget.constrain_as_public_input(&mut layouter, &cert_merkle_root)?;
        }

        // Assign genesis certificate
        let genesis_msg: AssignedNative<_> =
            native_gadget.assign_as_public_input(&mut layouter, self.genesis_msg)?;
        let (genesis_vk_x, genesis_vk_y) = {
            let [vk_x, vk_y] = self.genesis_vk.map(|vk| vk.to_field()).transpose_array();
            let genesis_vk_x: AssignedNative<_> =
                native_gadget.assign_as_public_input(&mut layouter, vk_x)?;
            let genesis_vk_y: AssignedNative<_> =
                native_gadget.assign_as_public_input(&mut layouter, vk_y)?;
            (genesis_vk_x, genesis_vk_y)
        };

        {
            // Open msg hash to check the link between certificates
            // Select genesis msg if it is genesis or msg from inner public inputs otherwise.
            let preimage = self.cert_msg_preimage.transpose_array();
            let assigned_preimage = native_gadget.assign_many(&mut layouter, &preimage)?;
            let hash = sha256_chip.hash(&mut layouter, &assigned_preimage)?;

            let factor = F::from(256u64);
            let bases: Vec<_> = (0..32)
                .scan(F::ONE, |state, _| {
                    let out = *state;
                    *state *= factor;
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
                native_gadget.assert_equal(&mut layouter, &cert_msg, &hash_native)?;
            }

            // Read the value of next merkle root and current epoch
            // cardano_transactions_merkle_root(32) | bytes(32) | next_aggregate_verification_key(31) | bytes(44) | next_protocol_parameters(24) | bytes(32) | current_epoch(13) | bytes(8) | latest_block_number(19) | bytes(8)
            // todo: check field keywords(?)
            let current_epoch_bytes = assigned_preimage[208..216].to_vec();

            let (is_same_epoch, is_next_epoch) = {
                // Constraint the current epoch as public input
                let mut items = vec![];
                for (v, base) in current_epoch_bytes.into_iter().zip(bases.iter()) {
                    items.push((*base, v.into()));
                }
                let current_epoch =
                    native_gadget.linear_combination(&mut layouter, &items, F::ZERO)?;
                native_gadget.constrain_as_public_input(&mut layouter, &current_epoch)?;

                // Check if cert_current_epoch == sd_current_epoch + 1 or cert_current_epoch == sd_current_epoch
                let is_same_epoch =
                    native_gadget.is_equal(&mut layouter, &current_epoch, &ivc_current_epoch)?;
                let next_epoch =
                    native_gadget.add_constant(&mut layouter, &ivc_current_epoch, F::ONE)?;
                let is_next_epoch =
                    native_gadget.is_equal(&mut layouter, &next_epoch, &current_epoch)?;

                (is_same_epoch, is_next_epoch)
            };

            {
                // Check the link on merkle root
                let is_equal_current =
                    native_gadget.is_equal(&mut layouter, &cert_merkle_root, &ivc_merkle_root)?;

                let is_equal_next = native_gadget.is_equal(
                    &mut layouter,
                    &cert_merkle_root,
                    &ivc_next_merkle_root,
                )?;

                let is_current =
                    native_gadget.and(&mut layouter, &[is_equal_current, is_same_epoch])?;
                let is_next = native_gadget.and(&mut layouter, &[is_equal_next, is_next_epoch])?;
                let is_link_valid = native_gadget.or(&mut layouter, &[is_current, is_next])?;
                native_gadget.assert_equal_to_fixed(&mut layouter, &is_link_valid, true)?;
            }
        }

        {
            // Assign for inner circuit proof verification
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
                &[&[cert_merkle_root, cert_msg.clone()]],
                self.cert_proof.clone(),
            )?;
            cert_proof_acc.collapse(&mut layouter, &foreign_ecc_chip, &native_gadget)?;

            // Assign for self-proof verification
            let (ivc_domain, ivc_cs, ivc_vk_value) = &self.ivc_vk;
            let assigned_ivc_vk: AssignedVk<S> = verifier_chip.assign_vk_as_public_input(
                &mut layouter,
                IVC_SD_NAME,
                ivc_domain,
                ivc_cs,
                *ivc_vk_value,
            )?;

            // Update accumulator
            // Witness a proof and an accumulator that ensure the validity of `prev_state`.
            let ivc_acc = {
                let mut fixed_base_names = vec![String::from("com_instance")];
                fixed_base_names.extend(verifier::fixed_base_names::<S>(
                    IVC_SD_NAME,
                    ivc_cs.num_fixed_columns() + ivc_cs.num_selectors(),
                    ivc_cs.permutation().columns.len(),
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
                    self.ivc_acc.clone(),
                )?
            };

            // Public inputs for this IVC circuit:
            let assigned_pi = [
                vec![genesis_msg.clone(), genesis_vk_x, genesis_vk_y],
                vec![
                    ivc_state,
                    ivc_msg,
                    ivc_merkle_root,
                    ivc_next_merkle_root,
                    ivc_current_epoch,
                ],
                verifier_chip.as_public_input(&mut layouter, &assigned_cert_vk)?,
                verifier_chip.as_public_input(&mut layouter, &assigned_ivc_vk)?,
                verifier_chip.as_public_input(&mut layouter, &ivc_acc)?,
            ]
            .concat();

            // Verify a witnessed proof that ensures the validity of `prev_state`.
            // The proof is valid iff `proof_acc` satisfies the invariant.
            let mut ivc_proof_acc = verifier_chip.prepare(
                &mut layouter,
                &assigned_ivc_vk,
                &[("com_instance", id_point)],
                &[&assigned_pi],
                self.ivc_proof.clone(),
            )?;
            ivc_proof_acc.collapse(&mut layouter, &foreign_ecc_chip, &native_gadget)?;

            let mut acc = AssignedAccumulator::<S>::accumulate(
                &mut layouter,
                &verifier_chip,
                &native_gadget,
                &poseidon_chip,
                &[ivc_acc, ivc_proof_acc, cert_proof_acc],
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
    use crate::ivc_sd::{IvcCircuit, configure_ivc_circuit};
    use crate::merkle_tree::{MTLeaf, MerklePath, MerkleTree};
    use crate::protocol_message::{
        AggregateVerificationKey, ProtocolMessage, ProtocolMessagePartKey,
    };
    use crate::utils::jubjub_base_from_le_bytes;
    use crate::{
        AssignedNative, AssignedNativePoint, Bls12, CircuitTranscript, Instantiable, JubjubBase,
        KZGCommitmentScheme, MerkleRoot, Msg, Msm, ParamsKZG, PoseidonState, Transcript,
        create_proof, keygen_pk, keygen_vk_with_k, prepare,
        schnorr_signature::{
            Signature as SchnorrSignature, SigningKey as SchnorrSigningKey,
            VerificationKey as SchnorrVerificationKey,
        },
        unique_signature::{Signature, SigningKey, VerificationKey},
    };
    use crate::{certificate::Certificate, compact_std_lib};
    use ff::Field;
    use midnight_circuits::compact_std_lib::Relation;
    use midnight_proofs::dev::cost_model::circuit_model;
    use midnight_proofs::plonk::{ProvingKey, VerifyingKey};
    use midnight_proofs::utils::SerdeFormat;
    use rand_core::OsRng;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{BufReader, Cursor};
    use std::time::Instant;

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
        Msg,
        Vec<u8>,
        MerkleRoot,
        u64,
        SchnorrSignature,
        Certificate,
        Msg,
        Vec<u8>,
        MerkleRoot,
        MerkleRoot,
        u64,
        Vec<(MTLeaf, MerklePath, Signature, u32)>,
        Vec<F>,
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
        let (
            genesis_vk,
            genesis_msg,
            genesis_preimage,
            genesis_sig,
            genesis_epoch,
            genesis_next_merkle_root,
        ) = {
            let sk = SchnorrSigningKey::generate(&mut rng);
            let vk = SchnorrVerificationKey::from(&sk);
            let genesis_epoch = 5u64;
            let next_merkle_root = merkle_tree.root();

            let (msg, preimage) = {
                let mut protocol_message = ProtocolMessage::new();
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
            let sig = sk.sign(&[msg], &mut rng);
            sig.verify(&[msg], &vk).unwrap();
            (vk, msg, preimage, sig, genesis_epoch, next_merkle_root)
        };

        // Create a transaction certificate
        let (
            tx_msg,
            tx_preimage,
            tx_merkle_root,
            tx_next_merkle_root,
            tx_epoch,
            tx_witness,
            tx_instance,
        ) = {
            let current_epoch = genesis_epoch + 1;
            let latest_block_number = 100u64;
            let (msg, preimage) = {
                let mut protocol_message = ProtocolMessage::new();
                protocol_message.set_message_part(
                    ProtocolMessagePartKey::CardanoTransactionsMerkleRoot,
                    vec![3u8; 32],
                );
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
                protocol_message.set_message_part(
                    ProtocolMessagePartKey::LatestBlockNumber,
                    latest_block_number.to_le_bytes().into(),
                );
                let preimage = protocol_message.get_preimage();
                let msg = protocol_message.compute_hash();
                (jubjub_base_from_le_bytes(&msg), preimage)
            };

            let mut witness = vec![];
            for j in 0..quorum as usize {
                let usk = sks[j].clone();
                let uvk = leaves[j].0;
                let sig = usk.sign(&[genesis_next_merkle_root, msg], &mut OsRng);
                sig.verify(&[genesis_next_merkle_root, msg], &uvk).unwrap();

                let merkle_path = merkle_tree.get_path(j);
                let computed_root = merkle_path.compute_root(leaves[j]);
                assert_eq!(genesis_next_merkle_root, computed_root);

                // Any index is eligible as target is set to be the maximum
                witness.push((leaves[j], merkle_path, sig, (j + 1) as u32));
            }

            let instance = Certificate::format_instance(&(genesis_next_merkle_root, msg)).unwrap();
            (
                msg,
                preimage,
                genesis_next_merkle_root,
                genesis_next_merkle_root,
                current_epoch,
                witness,
                instance,
            )
        };

        (
            genesis_vk,
            genesis_msg,
            genesis_preimage,
            genesis_next_merkle_root,
            genesis_epoch,
            genesis_sig,
            relation,
            tx_msg,
            tx_preimage,
            tx_merkle_root,
            tx_next_merkle_root,
            tx_epoch,
            tx_witness,
            tx_instance,
        )
    }

    #[test]
    fn test_wrapper() {
        let srs = open(K);

        // Create genesis certificate
        let (
            genesis_vk,
            genesis_msg,
            genesis_preimage,
            genesis_next_merkle_root,
            genesis_epoch,
            genesis_sig,
            cert_relation,
            tx_msg,
            tx_preimage,
            tx_merkle_root,
            tx_next_merkle_root,
            tx_epoch,
            tx_witness,
            tx_instance,
        ) = setup();

        // Set up inner circuit
        println!("setting up certificate circuit...");
        const K_INNER: u32 = 13;
        let mut cert_srs = srs.clone();
        cert_srs.downsize(K_INNER);

        let start = Instant::now();
        let cert_vk = compact_std_lib::setup_vk(&cert_srs, &cert_relation);
        let cert_pk = compact_std_lib::setup_pk(&cert_relation, &cert_vk);
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("Certificate circuit vk pk generation took: {:?}", duration);

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

        let start = Instant::now();
        let cert_proof = compact_std_lib::prove::<Certificate, PoseidonState<F>>(
            &cert_srs,
            &cert_pk,
            &cert_relation,
            &(tx_merkle_root, tx_msg),
            tx_witness,
            OsRng,
        )
        .expect("Proof generation should not fail");
        let duration = start.elapsed(); // Measure the elapsed time after proof generation.
        println!("Cert circuit proof generation took: {:?}", duration);

        let cert_acc = {
            let cert_dual_msm = {
                let mut transcript =
                    CircuitTranscript::<PoseidonState<F>>::init_from_bytes(&cert_proof);
                prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
                    cert_vk.vk(),
                    &[&[C::identity()]],
                    &[&[&tx_instance]],
                    &mut transcript,
                )
                .expect("Problem preparing the certificate proof")
            };
            assert!(cert_dual_msm.clone().check(&cert_srs.verifier_params()));

            let mut cert_acc: Accumulator<S> = cert_dual_msm.into();
            cert_acc.extract_fixed_bases(&cert_fixed_bases);
            assert!(cert_acc.check(&cert_srs.s_g2().into(), &cert_fixed_bases));
            cert_acc.collapse();
            cert_acc
        };

        //Set up ivc circuit
        let mut ivc_cs = ConstraintSystem::default();
        configure_ivc_circuit(&mut ivc_cs);
        let ivc_domain = EvaluationDomain::new(ivc_cs.degree() as u32, K);

        let default_ivc_circuit = IvcCircuit {
            self_vk: (ivc_domain.clone(), ivc_cs.clone(), Value::unknown()),
            prev_state: Value::known(F::ZERO),
            prev_msg: Value::unknown(),
            prev_merkle_root: Value::unknown(),
            prev_next_merkle_root: Value::unknown(),
            prev_current_epoch: Value::unknown(),
            prev_proof: Value::unknown(),
            prev_acc: Value::unknown(),
            genesis_vk: Value::known(genesis_vk),
            genesis_msg: Value::known(genesis_msg),
            genesis_sig: Value::known(genesis_sig.clone()),
            inner_vk: (
                cert_vk.vk().get_domain().clone(),
                cert_vk.vk().cs().clone(),
                Value::known(cert_vk.vk().transcript_repr()),
            ),
            inner_merkle_root: Value::unknown(),
            inner_proof: Value::unknown(),
            inner_msg: Value::unknown(),
            msg_preimage: Value::known(genesis_preimage.clone().try_into().unwrap()),
        };

        {
            let circuit_model = circuit_model::<_, 48, 32>(&default_ivc_circuit);
            println!("IVC circuit {:?}", circuit_model);
        }

        let start = Instant::now();
        let ivc_vk = keygen_vk_with_k(&srs, &default_ivc_circuit, K).unwrap();
        let ivc_pk = keygen_pk(ivc_vk.clone(), &default_ivc_circuit).unwrap();
        println!("Computed IVC circuit vk and pk in {:?} s", start.elapsed());

        {
            let mut buffer = Cursor::new(Vec::new());
            // Serialize the MidnightVK instance to the buffer in the RawBytes format
            ivc_vk.write(&mut buffer, SerdeFormat::RawBytes).unwrap();
            // Get the size of the serialized MidnightVK
            println!("ivc_with_inner vk length {:?}", buffer.get_ref().len());
        }

        let mut ivc_fixed_bases = BTreeMap::new();
        ivc_fixed_bases.insert(String::from("com_instance"), C::identity());
        ivc_fixed_bases.extend(verifier::fixed_bases::<S>(IVC_SD_NAME, &ivc_vk));
        let ivc_fixed_base_names = ivc_fixed_bases.keys().cloned().collect::<Vec<_>>();
        println!(
            "IVC fixed base name length {:?}",
            ivc_fixed_base_names.len()
        );

        let mut ivc_cert_fixed_bases = BTreeMap::new();
        ivc_cert_fixed_bases.extend(cert_fixed_bases.clone());
        ivc_cert_fixed_bases.extend(ivc_fixed_bases.clone());
        let ivc_cert_fixed_base_names = ivc_cert_fixed_bases.keys().cloned().collect::<Vec<_>>();
        println!(
            "Combined fixed base name length {:?}",
            ivc_cert_fixed_base_names.len()
        );

        let ivc_acc = Accumulator::<S>::new(
            Msm::new(&[C::default()], &[F::ONE], &BTreeMap::new()),
            Msm::new(
                &[C::default()],
                &[F::ONE],
                &ivc_cert_fixed_base_names
                    .iter()
                    .map(|name| (name.clone(), F::ZERO))
                    .collect(),
            ),
        );

        let ivc_circuit = IvcCircuit {
            self_vk: (
                ivc_domain.clone(),
                ivc_cs.clone(),
                Value::known(ivc_vk.transcript_repr()),
            ),
            prev_state: Value::known(F::ZERO),
            prev_msg: Value::known(F::ZERO),
            prev_merkle_root: Value::known(F::ZERO),
            prev_next_merkle_root: Value::known(F::ZERO),
            prev_current_epoch: Value::known(F::ZERO),
            prev_proof: Value::known(vec![]),
            prev_acc: Value::known(ivc_acc.clone()),
            genesis_vk: Value::known(genesis_vk),
            genesis_msg: Value::known(genesis_msg),
            genesis_sig: Value::known(genesis_sig.clone()),
            inner_vk: (
                cert_vk.vk().get_domain().clone(),
                cert_vk.vk().cs().clone(),
                Value::known(cert_vk.vk().transcript_repr()),
            ),
            inner_merkle_root: Value::known(tx_merkle_root),
            inner_msg: Value::known(tx_msg),
            inner_proof: Value::known(vec![]),
            msg_preimage: Value::known(genesis_preimage.try_into().unwrap()),
        };

        // Set public inputs [genesis_msg, genesis_vk, state, msg, merkle_root, next_merkle_root, current_epoch, inner_vk, self_vk, acc]
        let public_inputs = [
            AssignedNative::<F>::as_public_input(&genesis_msg),
            AssignedNativePoint::<Jubjub>::as_public_input(&genesis_vk.0),
            AssignedNative::<F>::as_public_input(&F::ONE),
            AssignedNative::<F>::as_public_input(&genesis_msg),
            AssignedNative::<F>::as_public_input(&F::ZERO),
            AssignedNative::<F>::as_public_input(&genesis_next_merkle_root),
            AssignedNative::<F>::as_public_input(&F::from(genesis_epoch)),
            AssignedVk::<S>::as_public_input(&cert_vk.vk()),
            AssignedVk::<S>::as_public_input(&ivc_vk),
            AssignedAccumulator::as_public_input(&ivc_acc),
        ]
        .concat();

        println!("instance length {:?}", public_inputs.len());

        let start = Instant::now();
        let ivc_proof = {
            let mut transcript = CircuitTranscript::<PoseidonState<F>>::init();
            let res = create_proof::<
                F,
                KZGCommitmentScheme<E>,
                CircuitTranscript<PoseidonState<F>>,
                IvcCircuit,
            >(
                &srs,
                &ivc_pk,
                &[ivc_circuit.clone()],
                1,
                &[&[&[], &public_inputs]],
                OsRng,
                &mut transcript,
            );
            if res.is_err() {
                println!("create proof error {:?}", res);
                panic!();
            }
            transcript.finalize()
        };
        println!("\n0-th IVC proof created in {:?}", start.elapsed());
        println!("IVC proof size {:?}", ivc_proof.len());

        let ivc_proof_acc: Accumulator<S> = {
            let start = Instant::now();
            let mut transcript = CircuitTranscript::<PoseidonState<F>>::init_from_bytes(&ivc_proof);
            let dual_msm =
                prepare::<F, KZGCommitmentScheme<E>, CircuitTranscript<PoseidonState<F>>>(
                    &ivc_vk,
                    &[&[C::identity()]],
                    &[&[&public_inputs]],
                    &mut transcript,
                )
                .expect("Verification failed");
            assert!(dual_msm.clone().check(&srs.verifier_params()));
            let duration = start.elapsed(); // Measure the elapsed time after proof generation.
            println!("IVC proof verification took: {:?}", duration);

            let mut proof_acc: Accumulator<S> = dual_msm.into();
            proof_acc.extract_fixed_bases(&ivc_fixed_bases);
            proof_acc.collapse();
            proof_acc
        };

        // Set up wrapper circuit
        let wrapper_circuit = WrapperCircuit {
            ivc_vk: (
                ivc_domain.clone(),
                ivc_cs.clone(),
                Value::known(ivc_vk.transcript_repr()),
            ),
            ivc_state: Value::known(F::ONE),
            ivc_msg: Value::known(genesis_msg),
            ivc_merkle_root: Value::known(F::ZERO),
            ivc_next_merkle_root: Value::known(genesis_next_merkle_root),
            ivc_current_epoch: Value::known(F::from(genesis_epoch)),
            ivc_proof: Value::known(ivc_proof),
            ivc_acc: Value::known(ivc_acc.clone()),
            genesis_vk: Value::known(genesis_vk),
            genesis_msg: Value::known(genesis_msg),
            cert_vk: (
                cert_vk.vk().get_domain().clone(),
                cert_vk.vk().cs().clone(),
                Value::known(cert_vk.vk().transcript_repr()),
            ),
            cert_merkle_root: Value::known(tx_merkle_root),
            cert_msg: Value::known(tx_msg),
            cert_proof: Value::known(cert_proof),
            cert_msg_preimage: Value::known(tx_preimage.try_into().unwrap()),
        };

        {
            let circuit_model = circuit_model::<_, 48, 32>(&wrapper_circuit);
            println!("\nWrapper circuit {:?}", circuit_model);
        }

        let start = Instant::now();
        let wrapper_vk: VerifyingKey<_, KZGCommitmentScheme<_>> =
            keygen_vk_with_k(&srs, &wrapper_circuit, K).unwrap();
        let wrapper_pk: ProvingKey<_, _> = keygen_pk(wrapper_vk.clone(), &wrapper_circuit).unwrap();
        println!(
            "Computed wrapper circuit vk and pk in {:?} s",
            start.elapsed()
        );

        {
            let mut buffer = Cursor::new(Vec::new());
            // Serialize the MidnightVK instance to the buffer in the RawBytes format
            wrapper_vk
                .write(&mut buffer, SerdeFormat::RawBytes)
                .unwrap();
            // Get the size of the serialized MidnightVK
            println!("wrapper vk length {:?}", buffer.get_ref().len());
        }

        // Accumulate cert_acc and ivc_proof_acc
        let wrapper_acc = {
            let mut accumulated = Accumulator::accumulate(&[ivc_acc, ivc_proof_acc, cert_acc]);
            accumulated.collapse();

            assert!(
                accumulated.check(&srs.s_g2().into(), &ivc_cert_fixed_bases),
                "IVC and cert acc verification failed"
            );
            accumulated
        };

        // Public inputs for wrapper circuit
        // [tx_msg, tx_merkle_root, genesis_msg, genesis_vk, current_epoch, tx_vk, ivc_vk, acc]
        let wrapper_public_inputs = [
            AssignedNative::<F>::as_public_input(&tx_msg),
            AssignedNative::<F>::as_public_input(&tx_merkle_root),
            AssignedNative::<F>::as_public_input(&genesis_msg),
            AssignedNativePoint::<Jubjub>::as_public_input(&genesis_vk.0),
            AssignedNative::<F>::as_public_input(&F::from(tx_epoch)),
            AssignedVk::<S>::as_public_input(&cert_vk.vk()),
            AssignedVk::<S>::as_public_input(&ivc_vk),
            AssignedAccumulator::as_public_input(&wrapper_acc),
        ]
        .concat();
        println!(
            "Wrapper circuit instance length {:?}",
            wrapper_public_inputs.len()
        );

        let start = Instant::now();
        let wrapper_proof = {
            let mut transcript = CircuitTranscript::<blake2b_simd::State>::init();
            let res = create_proof::<
                F,
                KZGCommitmentScheme<E>,
                CircuitTranscript<blake2b_simd::State>,
                WrapperCircuit,
            >(
                &srs,
                &wrapper_pk,
                &[wrapper_circuit.clone()],
                1,
                &[&[&[], &wrapper_public_inputs]],
                OsRng,
                &mut transcript,
            );
            if res.is_err() {
                println!("create proof error {:?}", res);
                panic!();
            }
            transcript.finalize()
        };
        println!("\nWrapper proof created in {:?}", start.elapsed());
        println!("Wrapper proof size {:?}", wrapper_proof.len());

        // Verify wrapper proof and accumulator together
        {
            // todo: combine the pairing check of wrapper_dual_msm and wrapper_acc for optimisation
            let start = Instant::now();
            let total = 100;
            for _ in 0..total {
                {
                    let mut transcript =
                        CircuitTranscript::<blake2b_simd::State>::init_from_bytes(&wrapper_proof);
                    let wrapper_dual_msm = prepare::<
                        F,
                        KZGCommitmentScheme<E>,
                        CircuitTranscript<blake2b_simd::State>,
                    >(
                        &wrapper_vk,
                        &[&[C::identity()]],
                        &[&[&wrapper_public_inputs]],
                        &mut transcript,
                    )
                    .expect("Verification failed");
                    assert!(wrapper_dual_msm.clone().check(&srs.verifier_params()));
                };

                assert!(
                    wrapper_acc.check(&srs.s_g2().into(), &ivc_cert_fixed_bases),
                    "Wrapper acc verification failed"
                );
            }

            println!("\nWrapper proof verified in {:?}", start.elapsed() / total);
        }
    }
}
