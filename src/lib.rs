pub mod alba;
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

use midnight_circuits::{
    compact_std_lib::{self, MidnightCircuit, Relation, ZkStdLib, ZkStdLibArch},
    ecc::{
        curves::CircuitCurve,
        foreign::{ForeignEccChip, ForeignEccConfig, nb_foreign_ecc_chip_columns},
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
        native::{NB_ARITH_COLS, NB_ARITH_FIXED_COLS},
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
        AssignedBit, AssignedForeignPoint, AssignedNative, AssignedNativePoint,
        AssignedScalarOfNativeCurve, ComposableChip, Instantiable,
    },
    verifier::{
        self, Accumulator, AssignedAccumulator, AssignedVk, BlstrsEmulation, Msm, SelfEmulation,
        VerifierGadget,
    },
};

use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, create_proof, keygen_pk, keygen_vk_with_k, prepare},
    poly::kzg::params::ParamsKZG,
    poly::{EvaluationDomain, kzg::KZGCommitmentScheme},
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
pub const DST_ALBA_ROUND: JubjubBase = JubjubBase::from_raw([4, 4, 0, 0]);
pub const DST_ALBA_BIN: JubjubBase = JubjubBase::from_raw([4, 5, 0, 0]);
pub const DST_ALBA_FINAL: JubjubBase = JubjubBase::from_raw([4, 6, 0, 0]);
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
            DST_ALBA_ROUND,
            DST_ALBA_BIN,
            DST_ALBA_FINAL,
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
