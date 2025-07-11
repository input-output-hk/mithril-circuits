use crate::{
    AssertionInstructions, AssignedNativePoint, AssignmentInstructions, ConversionInstructions,
    EccInstructions, Error, Jubjub, JubjubBase, JubjubSubgroup, Layouter, PublicInputInstructions,
    Relation, ScalarVar, Signature, Value, VerificationKey, ZkStdLib, ZkStdLibArch,
};

use group::Group;

type F = JubjubBase;

#[derive(Clone, Default, Debug)]
pub struct Certificate;

impl Relation for Certificate {
    // msg
    type Instance = F;

    // (vk, sigma, s, c)
    type Witness = (VerificationKey, Signature);

    fn format_instance(instance: &Self::Instance) -> Vec<F> {
        vec![*instance]
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let vk = std_lib
            .jubjub()
            .assign(layouter, witness.clone().map(|(x, _)| x.0))?;
        let sigma = std_lib
            .jubjub()
            .assign(layouter, witness.clone().map(|(_, sig)| sig.sigma))?;
        let s: ScalarVar<Jubjub> = std_lib
            .jubjub()
            .assign(layouter, witness.clone().map(|(_, sig)| sig.s))?;
        let c_native = std_lib.assign(layouter, witness.map(|(_, sig)| sig.c))?;
        let c: ScalarVar<Jubjub> = std_lib.jubjub().convert(layouter, &c_native)?;

        let msg = std_lib.assign_as_public_input(layouter, instance)?;
        let hash = std_lib.hash_to_curve(layouter, &[msg])?;

        let generator: AssignedNativePoint<Jubjub> = std_lib
            .jubjub()
            .assign_fixed(layouter, <JubjubSubgroup as Group>::generator())?;

        // compute R1
        let sigma_neg = std_lib.jubjub().negate(layouter, &sigma)?;
        let cap_r_1 = std_lib.jubjub().msm(
            layouter,
            &[s.clone(), c.clone()],
            &[hash.clone(), sigma_neg],
        )?;

        // compute R2
        let vk_neg = std_lib.jubjub().negate(layouter, &vk)?;
        let cap_r_2 = std_lib
            .jubjub()
            .msm(layouter, &[s, c], &[generator.clone(), vk_neg])?;

        // compute H2(g, H1(msg), vk, sigma, R1, R2)
        let gx = std_lib.jubjub().x_coordinate(&generator);
        let gy = std_lib.jubjub().y_coordinate(&generator);
        let hx = std_lib.jubjub().x_coordinate(&hash);
        let hy = std_lib.jubjub().y_coordinate(&hash);
        let vk_x = std_lib.jubjub().x_coordinate(&vk);
        let vk_y = std_lib.jubjub().y_coordinate(&vk);
        let sigma_x = std_lib.jubjub().x_coordinate(&sigma);
        let sigma_y = std_lib.jubjub().y_coordinate(&sigma);
        let cap_r_1_x = std_lib.jubjub().x_coordinate(&cap_r_1);
        let cap_r_1_y = std_lib.jubjub().y_coordinate(&cap_r_1);
        let cap_r_2_x = std_lib.jubjub().x_coordinate(&cap_r_2);
        let cap_r_2_y = std_lib.jubjub().y_coordinate(&cap_r_2);

        let c_prime = std_lib.poseidon(
            layouter,
            &[
                gx, gy, hx, hy, vk_x, vk_y, sigma_x, sigma_y, cap_r_1_x, cap_r_1_y, cap_r_2_x,
                cap_r_2_y,
            ],
        )?;

        std_lib.assert_equal(layouter, &c_native, &c_prime)
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            poseidon: true,
            sha256: None,
            secp256k1: false,
            bls12_381: false,
            base64: false,
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(Certificate)
    }
}

// decompose_fixed_limb_size
