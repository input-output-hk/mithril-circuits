use crate::{
    ArithInstructions, AssertionInstructions, AssignedBit, AssignedNative, AssignmentInstructions,
    BinaryInstructions, EqualityInstructions, Error, JubjubBase, Layouter, RangeCheckInstructions,
    ZkStdLib,
    utils::{big_to_fe, fe_to_big, split},
};
use ff::{Field, PrimeField};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;

pub mod certificate;
pub mod ivc;
pub mod ivc_with_inner;

pub fn div_rem_native_by_base(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<JubjubBase>,
    x: &AssignedNative<JubjubBase>,
    x_size_bound: u32,
    base: u32,
) -> Result<(AssignedNative<JubjubBase>, AssignedNative<JubjubBase>), Error> {
    assert!(x_size_bound < JubjubBase::NUM_BITS);

    let base_big = BigUint::from(base);
    let (q_value, r_value) = x
        .value()
        .map(|v| {
            let (q, r) = fe_to_big(*v).div_rem(&base_big);
            (big_to_fe(q), big_to_fe(r))
        })
        .unzip();
    // let shifted_x_size_bound = max(x_size_bound, LOG2_BASE) - LOG2_BASE;
    let q_bound = ((BigUint::one() << x_size_bound) + &base) / &base;
    let q = std_lib.assign_lower_than_fixed(layouter, q_value, &q_bound)?;
    let r = std_lib.assign_lower_than_fixed(layouter, r_value, &base_big)?;

    let q_times_base_plus_r = std_lib.linear_combination(
        layouter,
        &[
            (JubjubBase::from(base as u64), q.clone()),
            (JubjubBase::ONE, r.clone()),
        ],
        JubjubBase::ZERO,
    )?;
    std_lib.assert_equal(layouter, x, &q_times_base_plus_r)?;

    Ok((q, r))
}

// Compare x < y where x, y are 255-bit
pub fn lower_than_native(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<JubjubBase>,
    x: &AssignedNative<JubjubBase>,
    y: &AssignedNative<JubjubBase>,
) -> Result<AssignedBit<JubjubBase>, Error> {
    // decompose 255-bit value into 127-bit and 128-bit values.
    let x_value = x.value();
    let base127 = JubjubBase::from_u128(1_u128 << 127);
    let (x_low, x_high) = x_value.map(|v| split(v, 127)).unzip();
    let x_low_assigned: AssignedNative<_> = std_lib.assign(layouter, x_low.clone())?;
    let x_high_assigned: AssignedNative<_> = std_lib.assign(layouter, x_high.clone())?;

    let x_combined: AssignedNative<_> = std_lib.linear_combination(
        layouter,
        &[
            (JubjubBase::ONE, x_low_assigned.clone()),
            (base127, x_high_assigned.clone()),
        ],
        JubjubBase::ZERO,
    )?;
    std_lib.assert_equal(layouter, x, &x_combined)?;

    let y_value = y.value();
    let (y_low, y_high) = y_value.map(|v| split(v, 127)).unzip();
    let y_low_assigned: AssignedNative<_> = std_lib.assign(layouter, y_low.clone())?;
    let y_high_assigned: AssignedNative<_> = std_lib.assign(layouter, y_high.clone())?;

    let y_combined = std_lib.linear_combination(
        layouter,
        &[
            (JubjubBase::ONE, y_low_assigned.clone()),
            (base127, y_high_assigned.clone()),
        ],
        JubjubBase::ZERO,
    )?;
    std_lib.assert_equal(layouter, y, &y_combined)?;

    // Check if x < y
    let is_equal_high = std_lib.is_equal(layouter, &x_high_assigned, &y_high_assigned)?;
    let is_less_low = std_lib.lower_than(layouter, &x_low_assigned, &y_low_assigned, 127)?;
    let is_less_high = std_lib.lower_than(layouter, &x_high_assigned, &y_high_assigned, 128)?;

    let low_less = std_lib.and(layouter, &[is_equal_high, is_less_low])?;
    std_lib.or(layouter, &[is_less_high, low_less])
}

// check if x = 0 mod n
pub fn is_divisible_by_base(
    std_lib: &ZkStdLib,
    layouter: &mut impl Layouter<JubjubBase>,
    x: &AssignedNative<JubjubBase>,
    x_size_bound: u32,
    base: u32,
) -> Result<AssignedNative<JubjubBase>, Error> {
    assert!(x_size_bound < JubjubBase::NUM_BITS);

    let base_big = BigUint::from(base);
    let q_value = x.value().map(|v| {
        let (q, _) = fe_to_big(*v).div_rem(&base_big);
        big_to_fe(q)
    });

    let q_bound = ((BigUint::one() << x_size_bound) + &base) / &base;
    let q = std_lib.assign_lower_than_fixed(layouter, q_value, &q_bound)?;

    let q_times_base = std_lib.linear_combination(
        layouter,
        &[(JubjubBase::from(base as u64), q.clone())],
        JubjubBase::ZERO,
    )?;
    std_lib.assert_equal(layouter, x, &q_times_base)?;

    Ok(q)
}
