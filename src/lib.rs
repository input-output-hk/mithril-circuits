pub mod circuits;
pub mod lottery;
pub mod merkle_tree;
pub mod protocol_message;
pub mod signatures;
pub mod utils;

pub use midnight_curves::{
    Bls12, EDWARDS_D, Fq as JubjubBase, Fq as BlsScalar, Fr as JubjubScalar,
    G1Affine as BlstG1Affine, G1Projective as BlstG1, G2Affine as BlstG2Affine, JubjubAffine,
    JubjubExtended as Jubjub, JubjubSubgroup, MODULUS, pairing,
};

pub use circuits::*;
pub use signatures::*;

pub use midnight_zk_stdlib::{
    MidnightCircuit, Relation, ZkStdLib, ZkStdLibArch,
    utils::plonk_api::{SrsSource, load_srs, srs_for_test},
};

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
        PublicInputInstructions, RangeCheckInstructions, ZeroInstructions, hash::HashCPU,
    },
    types::{
        AssignedBit, AssignedByte, AssignedForeignPoint, AssignedNative, AssignedNativePoint,
        AssignedScalarOfNativeCurve, ComposableChip, InnerValue, Instantiable,
    },
    verifier::{
        self, Accumulator, AssignedAccumulator, AssignedKZGMultiCommitment, AssignedVk,
        BlstrsEmulation, InCircuitKZG, Msm, Point, SelfEmulation, VerifierGadget,
    },
};

pub use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::cost_model::circuit_model,
    plonk::{
        Circuit, ConstraintSystem, Error, VerifyingKey, create_proof, keygen_pk, keygen_vk_with_k,
        prepare,
    },
    poly::kzg::params::ParamsKZG,
    poly::{
        EvaluationDomain, PolynomialLabel,
        kzg::{KZGCommitmentScheme, commitment::KZGMultiCommitment, msm::DualMSM},
    },
    transcript::{CircuitTranscript, Transcript},
};

/// Number of advice columns used by the native arithmetic chip in the
/// hand-rolled IVC circuits of this crate.
///
/// `midnight-circuits` used to export this as a compile-time constant; since
/// the arithmetic column count became configurable (PR #287) only the lower
/// bound [`MIN_NB_ARITH_COLS`] is exported. We keep the historical value so
/// the column layout (and hence `k`) of the IVC circuits is unchanged.
pub const NB_ARITH_COLS: usize = MIN_NB_ARITH_COLS;
/// Number of fixed columns required by the native arithmetic chip for
/// [`NB_ARITH_COLS`] advice columns.
pub const NB_ARITH_FIXED_COLS: usize = NB_ARITH_COLS + NB_EXTRA_ARITH_FIXED_COLS;

type JubjubHashToCurve = HashToCurveGadget<
    JubjubBase,
    Jubjub,
    AssignedNative<JubjubBase>,
    PoseidonChip<JubjubBase>,
    EccChip<Jubjub>,
>;

type PoseidonHash = PoseidonChip<JubjubBase>;

pub type Msg = JubjubBase;
pub type Target = JubjubBase;
pub type MerkleRoot = JubjubBase;
pub type LotteryIndex = u32;
pub type SignerIndex = u32;

pub const DST_MERKLE_LEAF: JubjubBase = JubjubBase::from_raw([0, 0, 0, 0]);
pub const DST_MERKLE_NODE: JubjubBase = JubjubBase::from_raw([1, 1, 0, 0]);
pub const DST_UNIQUE_SIGNATURE: JubjubBase = JubjubBase::from_raw([2, 2, 0, 0]);
pub const DST_SCHNORR_SIGNATURE: JubjubBase = JubjubBase::from_raw([2, 3, 0, 0]);
pub const DST_LOTTERY: JubjubBase = JubjubBase::from_raw([3, 3, 0, 0]);
pub const DST_PERMUTATION: JubjubBase = JubjubBase::from_raw([5, 5, 0, 0]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dst_constants_are_unique() {
        let dsts = vec![
            DST_MERKLE_LEAF,
            DST_MERKLE_NODE,
            DST_UNIQUE_SIGNATURE,
            DST_SCHNORR_SIGNATURE,
            DST_LOTTERY,
            DST_PERMUTATION,
        ];

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
