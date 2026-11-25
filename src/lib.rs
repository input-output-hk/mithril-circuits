//! Native primitives and SNARK circuits for stake-weighted certificates.
//!
//! Registration is responsible for validating the registry and deriving lottery
//! targets from signer stakes and the total stake. It commits each verification
//! key and target in a Poseidon Merkle tree. Certificate proofs authenticate the
//! committed entries against the public registry root and check signatures and
//! lottery eligibility at a quorum of distinct lottery indices.
//!
//! The [`circuits`] module provides a topic-only circuit and a circuit with
//! separate topic and full-message signatures. Native operations live in
//! [`schnorr_signature`], [`merkle_tree`], and [`lottery`]. Messages are slices
//! of field elements; callers choose their application encoding before signing.
//! [`circuits::ivc_one`] recursively chains either certificate variant, with
//! genesis authentication, epoch transitions, and a public KZG accumulator.
//!
//! The compact Schnorr scheme combines a deterministic tag with a randomized
//! Chaum-Pedersen proof. Only the tag supplies the lottery projection. The
//! [`schnorr_signature`] module documents the transcript, sign convention, and
//! conversion of the base-field challenge to a curve scalar.
//!
//! # Native signing example
//!
//! ```
//! use snark_stms::{
//!     JubjubBase,
//!     schnorr_signature::{SigningKey, VerificationKey},
//! };
//! use rand_core::OsRng;
//!
//! let mut rng = OsRng;
//! let sk = SigningKey::generate(&mut rng);
//! let vk = VerificationKey::from(&sk);
//! let message = [JubjubBase::from(7), JubjubBase::from(42)];
//! let signature = sk.sign(&message, &mut rng);
//! signature.verify(&message, &vk)?;
//! # Ok::<(), snark_stms::SignatureError>(())
//! ```
//!
//! Build the API reference with `cargo doc --no-deps --open`. Certificate proof
//! tests load KZG parameters from `SRS_FILE` when set, or from `examples/assets/`
//! otherwise. The setup binary and example generate those files for testing
//! and benchmarking.

pub mod circuits;
pub mod lottery;
pub mod merkle_tree;
pub mod schnorr_signature;
pub mod utils;

pub use midnight_curves::{
    Bls12, Fq as JubjubBase, Fr as JubjubScalar, JubjubAffine, JubjubExtended as Jubjub,
    JubjubSubgroup,
};

pub use circuits::*;
pub use schnorr_signature::SignatureError;

pub use midnight_zk_stdlib::{MidnightCircuit, Relation, ZkStdLib, ZkStdLibArch};

pub use midnight_circuits::{
    ecc::{
        curves::CircuitCurve,
        foreign::weierstrass_chip::{
            ForeignWeierstrassEccChip as ForeignEccChip,
            ForeignWeierstrassEccConfig as ForeignEccConfig, nb_foreign_ecc_chip_columns,
        },
        hash_to_curve::HashToCurveGadget,
        native::{EccChip, EccConfig, NB_EDWARDS_COLS},
    },
    field::{
        NativeChip, NativeConfig, NativeGadget,
        decomposition::{
            chip::{P2RDecompositionChip, P2RDecompositionConfig},
            pow2range::Pow2RangeChip,
        },
        foreign::FieldChip,
        native::{MIN_NB_ARITH_COLS, NB_EXTRA_ARITH_FIXED_COLS},
    },
    hash::poseidon::{
        NB_POSEIDON_ADVICE_COLS, NB_POSEIDON_FIXED_COLS, PoseidonChip, PoseidonConfig,
        PoseidonState,
    },
    instructions::{
        ArithInstructions, AssertionInstructions, AssignmentInstructions, BinaryInstructions,
        ControlFlowInstructions, ConversionInstructions, DecompositionInstructions,
        EccInstructions, EqualityInstructions, HashInstructions, HashToCurveCPU,
        PublicInputInstructions, ZeroInstructions, hash::HashCPU,
    },
    types::{
        AssignedBit, AssignedByte, AssignedNative, AssignedNativePoint,
        AssignedScalarOfNativeCurve, ComposableChip, InnerValue, Instantiable,
    },
    verifier::{
        self, Accumulator, AssignedAccumulator, AssignedVk, BlstrsEmulation, Msm, Point,
        SelfEmulation, VerifierGadget,
    },
};

pub use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::cost_model::circuit_model,
    plonk::{
        Circuit, ConstraintSystem, Error, VerifyingKey, create_proof, keygen_pk, keygen_vk_with_k,
        prepare,
    },
    poly::{
        EvaluationDomain, PolynomialLabel,
        kzg::{KZGCommitmentScheme, msm::DualMSM, params::ParamsKZG},
    },
    transcript::{CircuitTranscript, Transcript},
};

type JubjubHashToCurve = HashToCurveGadget<
    JubjubBase,
    Jubjub,
    AssignedNative<JubjubBase>,
    PoseidonChip<JubjubBase>,
    EccChip<Jubjub>,
>;

type PoseidonHash = PoseidonChip<JubjubBase>;

/// Advice-column count used by the recursive circuit's native arithmetic chip.
pub const NB_ARITH_COLS: usize = MIN_NB_ARITH_COLS;
/// Fixed-column count corresponding to [`NB_ARITH_COLS`].
pub const NB_ARITH_FIXED_COLS: usize = NB_ARITH_COLS + NB_EXTRA_ARITH_FIXED_COLS;

/// One field element representing an encoded topic or message body.
pub type Msg = JubjubBase;
/// Inclusive upper bound on a field-valued lottery evaluation.
pub type Target = JubjubBase;
/// Poseidon root committing to the membership registry.
pub type MerkleRoot = JubjubBase;
/// Zero-based lottery index, bounded by a certificate's lottery count.
pub type LotteryIndex = u32;

/// Domain tag for the compact Schnorr challenge hash.
///
/// The name refers to the deterministic lottery tag; the proof is randomized.
pub const DST_UNIQUE_SIGNATURE: JubjubBase = JubjubBase::from_raw([2, 2, 0, 0]);
/// Domain tag for the IVC genesis authority's Schnorr signature.
pub const DST_SCHNORR_SIGNATURE: JubjubBase = JubjubBase::from_raw([2, 3, 0, 0]);
/// Domain tag used to derive the lottery context prefix.
pub const DST_LOTTERY: JubjubBase = JubjubBase::from_raw([3, 3, 0, 0]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dst_constants_are_unique() {
        let dsts = vec![DST_UNIQUE_SIGNATURE, DST_SCHNORR_SIGNATURE, DST_LOTTERY];

        let mut sorted_dsts = dsts.clone();
        sorted_dsts.sort();

        // Check for duplicates
        for i in 0..sorted_dsts.len() - 1 {
            assert_ne!(
                sorted_dsts[i],
                sorted_dsts[i + 1],
                "Duplicate DST constant found: {:?}",
                sorted_dsts[i]
            );
        }
    }
}
