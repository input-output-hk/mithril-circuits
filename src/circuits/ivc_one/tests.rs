use super::*;
use crate::{
    MidnightCircuit, PoseidonState,
    circuits::{certificate_topicbody, certificate_topiconly, test_srs::load_srs},
    merkle_tree::{MTLeaf, MerkleTree},
    schnorr_signature::{SigningKey, VerificationKey},
};
use ff::Field;
use midnight_zk_stdlib as zk;
use rand_core::OsRng;

use super::{
    genesis_signature::{
        Signature as GenesisSignature, SigningKey as GenesisKey, VerificationKey as GenesisVk,
    },
    message::ProtocolMessage,
    proof::{IvcKeys, initial_accumulator, prove_step, verify},
    state::{State, Witness},
};

fn run_chain<R: IvcCertificate>(
    relation: R,
    root: F,
    make_witness: impl Fn(F, F, F) -> R::Witness,
) {
    let k_inner = MidnightCircuit::from_relation(&relation, None).k();
    let ivc_srs = load_srs(K);
    let mut cert_srs = ivc_srs.clone();
    cert_srs.downsize(k_inner);
    let cert_vk = zk::setup_vk(&cert_srs, &relation);
    let cert_pk = zk::setup_pk(&relation, &cert_vk);
    eprintln!("Setting up {} IVC keys", R::VARIANT.name());
    let keys = IvcKeys::setup(&ivc_srs, cert_vk.vk(), R::VARIANT).unwrap();
    let authority = GenesisKey::generate(&mut OsRng);
    let mut message = ProtocolMessage {
        digest: [1; 32],
        next_merkle_root: root,
        next_registry_size: 4,
        total_stake: 100,
        next_protocol_params: F::from(7),
        current_epoch: 5,
    };
    let genesis_msg = message.hash();
    let global = keys.global(genesis_msg, GenesisVk::from(&authority));
    let mut state = State::genesis();
    let mut acc = initial_accumulator(&global);
    let mut previous_proof = Vec::new();
    // Cover genesis, the first epoch, another certificate in that epoch, and the next epoch.
    for (index, epoch) in [5, 6, 6, 7].into_iter().enumerate() {
        message.current_epoch = epoch;
        message.digest = [index as u8 + 1; 32];
        if index == 3 {
            message.next_protocol_params = F::from(8);
        }
        let msg = message.hash();
        let topic = if R::VARIANT == CertificateVariant::TopicOnly {
            msg
        } else {
            F::from(42)
        };
        let signature = if index == 0 {
            authority.sign(&[genesis_msg], &mut OsRng)
        } else {
            GenesisSignature::default()
        };
        let witness = Witness::new(signature, root, topic, msg, message.preimage());
        let certificate = if index == 0 {
            Vec::new()
        } else {
            zk::prove::<R, PoseidonState<F>>(
                &cert_srs,
                &cert_pk,
                &relation,
                &R::instance(root, topic, msg),
                make_witness(root, topic, msg),
                OsRng,
            )
            .unwrap()
        };
        eprintln!("Proving {} IVC step {index}", R::VARIANT.name());
        let step = prove_step::<PoseidonState<F>>(
            &ivc_srs,
            &keys,
            &global,
            &state,
            &witness,
            &certificate,
            &previous_proof,
            &acc,
        )
        .unwrap();
        verify::<PoseidonState<F>>(&ivc_srs.verifier_params(), &global, &step).unwrap();
        assert_eq!(step.state.current_epoch, F::from(epoch));
        if R::VARIANT == CertificateVariant::TopicBody && index > 0 {
            assert_eq!(step.state.topic, F::from(42));
            assert_eq!(step.state.msg, msg);
        }
        let mut tampered = step.clone();
        tampered.state.msg += F::ONE;
        assert!(
            verify::<PoseidonState<F>>(&ivc_srs.verifier_params(), &global, &tampered).is_err()
        );
        let mut wrong_globals = global.clone();
        wrong_globals.genesis_msg += F::ONE;
        assert!(
            verify::<PoseidonState<F>>(&ivc_srs.verifier_params(), &wrong_globals, &step).is_err()
        );
        let mut tampered_acc = step.clone();
        tampered_acc.accumulator = initial_accumulator(&global);
        if index > 0 {
            assert!(
                verify::<PoseidonState<F>>(&ivc_srs.verifier_params(), &global, &tampered_acc)
                    .is_err()
            );
        }
        use super::io::{Read, Write};
        let mut encoded = Vec::new();
        step.accumulator
            .write(&mut encoded, midnight_proofs::utils::SerdeFormat::RawBytes)
            .unwrap();
        let decoded = crate::Accumulator::<S>::read(
            &mut encoded.as_slice(),
            midnight_proofs::utils::SerdeFormat::RawBytes,
        )
        .unwrap();
        use crate::{AssignedAccumulator, Instantiable};
        assert_eq!(
            AssignedAccumulator::as_public_input(&decoded),
            AssignedAccumulator::as_public_input(&step.accumulator)
        );
        state = step.state;
        acc = step.accumulator;
        previous_proof = step.proof;
    }
}

#[test]
fn test_ivc_topiconly() {
    let key = SigningKey::generate(&mut OsRng);
    let leaves = vec![MTLeaf(VerificationKey::from(&key), -F::ONE); 4];
    let tree = MerkleTree::create(&leaves);
    run_chain(
        certificate_topiconly::Certificate::new(1, 10, 2),
        tree.root(),
        |root, topic, _| {
            vec![(
                leaves[0],
                tree.get_path(0),
                key.sign(&[root, topic], &mut OsRng),
                0,
            )]
        },
    );
}

#[test]
fn test_ivc_topicbody() {
    let key = SigningKey::generate(&mut OsRng);
    let leaves = vec![MTLeaf(VerificationKey::from(&key), -F::ONE); 4];
    let tree = MerkleTree::create(&leaves);
    run_chain(
        certificate_topicbody::Certificate::new(1, 10, 2),
        tree.root(),
        |root, topic, msg| {
            vec![(
                leaves[0],
                tree.get_path(0),
                key.sign(&[root, topic], &mut OsRng),
                key.sign(&[root, topic, msg], &mut OsRng),
                0,
            )]
        },
    );
}

// Exercise transition constraints directly, including witnesses that the native
// prover rejects before attempting the expensive recursive proof.
#[derive(Clone)]
struct TransitionCircuit {
    variant: CertificateVariant,
    global: state::Global,
    previous: State,
    witness: Witness,
}

impl crate::Circuit<F> for TransitionCircuit {
    type Config = config::IvcConfig;
    type FloorPlanner = crate::SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut crate::ConstraintSystem<F>) -> Self::Config {
        config::configure_ivc_circuit(meta)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl crate::Layouter<F>,
    ) -> Result<(), crate::Error> {
        use crate::{BinaryInstructions, ComposableChip, Value};
        let gadget = gadget::IvcGadget::new(&config, self.variant);
        let domain_cs = (
            self.global.cert_vk.get_domain().clone(),
            self.global.cert_vk.cs().clone(),
        );
        let global = gadget.assign_global_as_public_input(
            &mut layouter,
            &Value::known(self.global.clone()),
            &domain_cs,
            &domain_cs,
        )?;
        let state = gadget.assign_state(&mut layouter, &Value::known(self.previous.clone()))?;
        let witness = gadget.assign_witness(&mut layouter, &Value::known(self.witness.clone()))?;
        let genesis = gadget.is_genesis(&mut layouter, &state)?;
        let not_genesis = gadget.native_gadget.not(&mut layouter, &genesis)?;
        gadget.assert_genesis(&mut layouter, &not_genesis, &global, &witness)?;
        let next = gadget.transition(
            &mut layouter,
            &genesis,
            &not_genesis,
            &global,
            &state,
            &witness,
        )?;
        gadget.constrain_state_as_public_input(&mut layouter, &next)?;
        gadget.core_decomp_chip.load(&mut layouter)?;
        gadget.sha2_256_chip.load(&mut layouter)
    }
}

fn check_transition(circuit: &TransitionCircuit, expected: &State) -> bool {
    let pi = [circuit.global.as_public_input(), expected.as_public_input()].concat();
    midnight_proofs::dev::MockProver::run(circuit, vec![vec![], pi])
        .unwrap()
        .verify()
        .is_ok()
}

#[test]
fn test_transition_rejects_invalid_links_and_messages() {
    use crate::HashCPU;
    use midnight_circuits::hash::sha256::Sha256Chip;
    let params = load_srs(13);
    let relation = certificate_topiconly::Certificate::new(1, 10, 0);
    let vk = zk::setup_vk(&params, &relation);
    let authority = GenesisKey::generate(&mut OsRng);
    let mut message = ProtocolMessage {
        digest: [1; 32],
        next_merkle_root: F::from(22),
        next_registry_size: 4,
        total_stake: 100,
        next_protocol_params: F::from(8),
        current_epoch: 6,
    };
    let global = state::Global::new(
        message.hash(),
        GenesisVk::from(&authority),
        vk.vk(),
        vk.vk(),
    );
    let previous = State::new(
        F::from(2),
        F::from(42),
        F::from(9),
        F::from(11),
        F::from(22),
        F::from(7),
        F::from(8),
        F::from(6),
    );
    let witness = Witness::new(
        GenesisSignature::default(),
        F::from(11),
        F::from(42),
        message.hash(),
        message.preimage(),
    );
    let mut circuit = TransitionCircuit {
        variant: CertificateVariant::TopicBody,
        global,
        previous,
        witness,
    };
    let expected = circuit
        .previous
        .advance(circuit.variant, &circuit.global, &circuit.witness)
        .unwrap();
    assert!(check_transition(&circuit, &expected));

    let mut invalid = circuit.clone();
    invalid.witness.cert_merkle_root += F::ONE;
    let mut candidate = expected.clone();
    candidate.merkle_root += F::ONE;
    assert!(
        invalid
            .previous
            .advance(invalid.variant, &invalid.global, &invalid.witness)
            .is_err()
    );
    assert!(!check_transition(&invalid, &candidate));

    let mut invalid = circuit.clone();
    invalid.witness.msg_preimage[6] ^= 1;
    assert!(!check_transition(&invalid, &expected));

    let mut invalid = circuit.clone();
    invalid.witness.msg_preimage[0] ^= 1;
    invalid.witness.cert_msg = crate::utils::jubjub_base_from_le_bytes(&Sha256Chip::<F>::hash(
        &invalid.witness.msg_preimage,
    ));
    let mut candidate = expected.clone();
    candidate.msg = invalid.witness.cert_msg;
    assert!(!check_transition(&invalid, &candidate));

    // An epoch jump is invalid even when the signed message hash is updated.
    let mut invalid = circuit.clone();
    message.current_epoch = 8;
    invalid.witness.msg_preimage = message.preimage();
    invalid.witness.cert_msg = message.hash();
    let mut candidate = expected.clone();
    candidate.msg = message.hash();
    candidate.current_epoch = F::from(8);
    assert!(!check_transition(&invalid, &candidate));

    // Next-epoch commitments cannot change between certificates of one epoch.
    message.current_epoch = 6;
    message.next_protocol_params = F::from(99);
    let mut invalid = circuit.clone();
    invalid.witness.msg_preimage = message.preimage();
    invalid.witness.cert_msg = message.hash();
    let mut candidate = expected.clone();
    candidate.msg = message.hash();
    candidate.next_protocol_params = F::from(99);
    assert!(!check_transition(&invalid, &candidate));
    message.next_protocol_params = F::from(8);
    message.next_merkle_root = F::from(99);
    let mut invalid = circuit.clone();
    invalid.witness.msg_preimage = message.preimage();
    invalid.witness.cert_msg = message.hash();
    let mut candidate = expected.clone();
    candidate.msg = message.hash();
    candidate.next_merkle_root = F::from(99);
    assert!(!check_transition(&invalid, &candidate));

    // At an epoch transition the new signer root must be the announced next root.
    let mut next_epoch = circuit.clone();
    let mut next_message = ProtocolMessage::from_preimage(&circuit.witness.msg_preimage).unwrap();
    next_message.current_epoch = 7;
    next_message.next_merkle_root = F::from(33);
    next_message.next_protocol_params = F::from(9);
    next_epoch.witness.cert_merkle_root = F::from(22);
    next_epoch.witness.cert_msg = next_message.hash();
    next_epoch.witness.msg_preimage = next_message.preimage();
    let next_state = next_epoch
        .previous
        .advance(next_epoch.variant, &next_epoch.global, &next_epoch.witness)
        .unwrap();
    assert_eq!(next_state.protocol_params, F::from(8));
    assert!(check_transition(&next_epoch, &next_state));
    let mut invalid = next_epoch;
    invalid.witness.cert_merkle_root = F::from(11);
    let mut candidate = next_state;
    candidate.merkle_root = F::from(11);
    assert!(!check_transition(&invalid, &candidate));

    let mut invalid = circuit.clone();
    invalid.previous.counter = F::ONE;
    let mut candidate = expected.clone();
    candidate.counter = F::from(2);
    assert!(!check_transition(&invalid, &candidate));

    // The same valid transition works in topic-only mode when topic == message.
    circuit.variant = CertificateVariant::TopicOnly;
    circuit.witness.cert_topic = circuit.witness.cert_msg;
    let expected = circuit
        .previous
        .advance(circuit.variant, &circuit.global, &circuit.witness)
        .unwrap();
    assert!(check_transition(&circuit, &expected));
    let mut invalid = circuit.clone();
    invalid.witness.cert_topic += F::ONE;
    let mut candidate = expected.clone();
    candidate.topic += F::ONE;
    assert!(!check_transition(&invalid, &candidate));

    // Genesis is bound to the trusted authority even with a correctly hashed message.
    circuit.previous = State::genesis();
    circuit.witness.msg_preimage = message.preimage();
    circuit.global.genesis_msg = message.hash();
    circuit.witness.genesis_sig = authority.sign(&[message.hash()], &mut OsRng);
    let expected = circuit
        .previous
        .advance(circuit.variant, &circuit.global, &circuit.witness)
        .unwrap();
    assert!(check_transition(&circuit, &expected));
    circuit.witness.genesis_sig.s += crate::JubjubScalar::ONE;
    assert!(!check_transition(&circuit, &expected));
}
