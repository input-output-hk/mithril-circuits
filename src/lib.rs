pub mod unique_signature;
pub mod circuits;

pub use blstrs::{
    Fq as JubjubBase, Fr as JubjubScalar, G1Projective as BlstG1, JubjubAffine,
    JubjubExtended as Jubjub, JubjubExtended, JubjubSubgroup, MODULUS,
};

pub use unique_signature::*;
pub use circuits::*;

use midnight_circuits::{
    compact_std_lib::{self, MidnightCircuit, Relation, ZkStdLib, ZkStdLibArch},
    ecc::{hash_to_curve::HashToCurveGadget, native::EccChip, native::ScalarVar, curves::CircuitCurve,
          foreign::{nb_foreign_ecc_chip_columns, ForeignEccChip, ForeignEccConfig},
    },
    instructions::{
        AssertionInstructions, AssignmentInstructions, ConversionInstructions, EccInstructions,
        HashToCurveCPU, PublicInputInstructions, hash::HashCPU, ArithInstructions, ZeroInstructions, BinaryInstructions,
    },
    field::{
        decomposition::{
            chip::{P2RDecompositionChip, P2RDecompositionConfig},
            pow2range::Pow2RangeChip,
        },
        foreign::FieldChip,
        native::NB_ARITH_COLS,
        NativeChip, NativeConfig, NativeGadget,
    },
    hash::poseidon::{
        PoseidonChip, PoseidonConfig, PoseidonState, NB_POSEIDON_ADVICE_COLS,
        NB_POSEIDON_FIXED_COLS,
    },
    types::{AssignedNativePoint, AssignedNative, ComposableChip, Instantiable},
    verifier::{self, Accumulator, AssignedAccumulator, AssignedVk, Msm, VerifierGadget},
};

use midnight_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{create_proof, keygen_pk, keygen_vk_with_k, prepare, Circuit, ConstraintSystem, Error},
    poly::{kzg::KZGCommitmentScheme, EvaluationDomain},
    transcript::{CircuitTranscript, Transcript},
    dev::CircuitCost,
};

type JubjubHashToCurve = HashToCurveGadget<
    JubjubBase,
    Jubjub,
    AssignedNative<JubjubBase>,
    PoseidonChip<JubjubBase>,
    EccChip<Jubjub>,
>;

type PoseidonHash = PoseidonChip<JubjubBase>;


