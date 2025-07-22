pub mod circuits;
pub mod lottery;
pub mod merkle_tree;
pub mod unique_signature;
pub mod utils;

pub use blstrs::{
    Fq as JubjubBase, Fr as JubjubScalar, G1Projective as BlstG1, JubjubAffine,
    JubjubExtended as Jubjub, JubjubExtended, JubjubSubgroup, MODULUS,
};

pub use circuits::*;
pub use unique_signature::*;

use midnight_circuits::{
    compact_std_lib::{self, MidnightCircuit, Relation, ZkStdLib, ZkStdLibArch},
    ecc::{
        curves::CircuitCurve,
        foreign::{ForeignEccChip, ForeignEccConfig, nb_foreign_ecc_chip_columns},
        hash_to_curve::HashToCurveGadget,
        native::EccChip,
        native::ScalarVar,
    },
    field::{
        NativeChip, NativeConfig, NativeGadget,
        decomposition::{
            chip::{P2RDecompositionChip, P2RDecompositionConfig},
            pow2range::Pow2RangeChip,
        },
        foreign::FieldChip,
        native::NB_ARITH_COLS,
    },
    hash::poseidon::{
        NB_POSEIDON_ADVICE_COLS, NB_POSEIDON_FIXED_COLS, PoseidonChip, PoseidonConfig,
        PoseidonState,
    },
    instructions::{
        ArithInstructions, AssertionInstructions, AssignmentInstructions, BinaryInstructions,
        ControlFlowInstructions, ConversionInstructions, EccInstructions, EqualityInstructions,
        HashToCurveCPU, PublicInputInstructions, ZeroInstructions, hash::HashCPU,
    },
    types::{AssignedBit, AssignedNative, AssignedNativePoint, ComposableChip, Instantiable},
    verifier::{self, Accumulator, AssignedAccumulator, AssignedVk, Msm, VerifierGadget},
};

use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, create_proof, keygen_pk, keygen_vk_with_k, prepare},
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
pub type Index = u32;
