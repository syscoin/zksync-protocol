use crate::field::SmallField;

use crate::cs::traits::cs::ConstraintSystem;
use crate::cs::Variable;

pub trait CSAllocatable<F: SmallField>: Sized {
    // quite restrictive, but we want to allow placing too many bounds everywhere.
    // In general it's easy to satisfy
    type Witness: 'static + Send + Sync + Clone + std::fmt::Debug + std::hash::Hash;

    fn placeholder_witness() -> Self::Witness;
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self;
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self;
    fn allocate_constant<CS: ConstraintSystem<F>>(_cs: &mut CS, _witness: Self::Witness) -> Self {
        unimplemented!("not implemented by default");
    }
}

pub trait CSPlaceholder<F: SmallField>: Sized {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self;
}

impl<F: SmallField> CSPlaceholder<F> for () {
    fn placeholder<CS: ConstraintSystem<F>>(_cs: &mut CS) -> Self {}
}

use crate::cs::traits::cs::DstBuffer;

pub trait CSAllocatableExt<F: SmallField>: CSAllocatable<F> {
    const INTERNAL_STRUCT_LEN: usize;

    // we should be able to allocate without knowing values yet
    fn witness_from_set_of_values(values: [F; Self::INTERNAL_STRUCT_LEN]) -> Self::Witness;
    fn create_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        // by default we can use unoptimized approach
        CSAllocatable::allocate_without_value(cs)
    }
    fn flatten_as_variables(&self) -> [Variable; Self::INTERNAL_STRUCT_LEN];
    fn from_variables_set(_variables: [Variable; Self::INTERNAL_STRUCT_LEN]) -> Self {
        unimplemented!("not always necessary by default")
    }
    /// NOTE: implementations SHOULD EXTEND/PUSH to buffer, so recursive composition is available
    fn set_internal_variables_values(witness: Self::Witness, dst: &mut DstBuffer<'_, '_, F>);
}

// we also want to provide some default implementations for future proc macroses
// and convenience in general

// Empty tuple
impl<F: SmallField> CSAllocatable<F> for () {
    type Witness = ();

    #[inline(always)]
    fn placeholder_witness() -> Self::Witness {}

    #[inline(always)]
    fn allocate_without_value<CS: ConstraintSystem<F>>(_cs: &mut CS) -> Self {}

    #[inline(always)]
    fn allocate<CS: ConstraintSystem<F>>(_cs: &mut CS, _witness: Self::Witness) -> Self {}

    #[inline(always)]
    fn allocate_constant<CS: ConstraintSystem<F>>(_cs: &mut CS, _witness: Self::Witness) -> Self {}
}

// Marker that we can use
impl<F: SmallField, T: 'static + Send + Sync + Clone> CSAllocatable<F>
    for std::marker::PhantomData<T>
{
    type Witness = std::marker::PhantomData<T>;

    #[inline(always)]
    fn placeholder_witness() -> Self::Witness {
        std::marker::PhantomData
    }

    #[inline(always)]
    fn allocate_without_value<CS: ConstraintSystem<F>>(_cs: &mut CS) -> Self {
        std::marker::PhantomData
    }

    #[inline(always)]
    fn allocate<CS: ConstraintSystem<F>>(_cs: &mut CS, _witness: Self::Witness) -> Self {
        std::marker::PhantomData
    }

    #[inline(always)]
    fn allocate_constant<CS: ConstraintSystem<F>>(_cs: &mut CS, _witness: Self::Witness) -> Self {
        std::marker::PhantomData
    }
}

// Array
impl<F: SmallField, T: CSAllocatable<F>, const N: usize> CSAllocatable<F> for [T; N] {
    type Witness = [T::Witness; N];

    #[inline(always)]
    fn placeholder_witness() -> Self::Witness {
        std::array::from_fn(|_| T::placeholder_witness())
    }

    #[inline(always)]
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        std::array::from_fn(|_| T::allocate_without_value(cs))
    }

    #[inline(always)]
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        witness.map(|el| T::allocate(cs, el))
    }

    #[inline(always)]
    fn allocate_constant<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        witness.map(|el| T::allocate_constant(cs, el))
    }
}

#[must_use]
pub fn allocate_num_elements<F: SmallField, CS: ConstraintSystem<F>, EL: CSAllocatable<F>>(
    cs: &mut CS,
    num_elements: usize,
    source: Option<impl Iterator<Item = EL::Witness>>,
) -> Vec<EL> {
    let mut result = Vec::with_capacity(num_elements);
    match source {
        Some(mut source) => {
            for idx in 0..num_elements {
                let witness = source
                    .next()
                    .unwrap_or_else(|| {
                        panic!(
                            "must contain enough elements: failed to get element {} (zero enumerated) from expected list of {}",
                            idx,
                            num_elements
                        )
                    });
                let el = EL::allocate(cs, witness);
                result.push(el);
            }

            assert!(source.next().is_none());
        }
        None => {
            for _ in 0..num_elements {
                let witness = EL::placeholder_witness();
                let el = EL::allocate(cs, witness);
                result.push(el);
            }
        }
    }

    result
}

#[cfg(test)]
mod initialized_gadget_arrays {
    use super::CSAllocatableExt;
    use crate::cs::Variable;
    use crate::field::{goldilocks::GoldilocksField as F, U64Representable};
    use crate::gadgets::{
        boolean::Boolean,
        num::Num,
        u16::UInt16,
        u160::{decompose_address_as_u32x5, UInt160},
        u256::{decompose_u256_as_u32x8, UInt256},
        u32::UInt32,
        u512::{decompose_u512_as_u32x16, UInt512},
        u8::UInt8,
    };
    use std::marker::PhantomData;

    #[test]
    fn scalar_variable_outputs_preserve_the_variable() {
        // SYSCOIN: Inspect variable ordering directly without introducing any
        // constraint-system allocation that could mask a placeholder leak.
        let variable = Variable::from_variable_index(19);
        macro_rules! check {
            ($gadget:ident) => {
                let value = $gadget::<F> {
                    variable,
                    _marker: PhantomData,
                };
                assert_eq!(value.flatten_as_variables(), [variable]);
            };
        }
        check!(Boolean);
        check!(Num);
        check!(UInt8);
        check!(UInt16);
        check!(UInt32);
    }

    #[test]
    fn limb_variable_outputs_preserve_every_position() {
        macro_rules! check {
            ($gadget:ident, $length:expr) => {
                let variables: [_; $length] =
                    std::array::from_fn(|i| Variable::from_variable_index((17 + i) as u64));
                let value = $gadget::<F> {
                    inner: variables.map(|variable| UInt32 {
                        variable,
                        _marker: PhantomData,
                    }),
                };
                assert_eq!(value.flatten_as_variables(), variables);
            };
        }
        check!(UInt160, 5);
        check!(UInt256, 8);
        check!(UInt512, 16);
    }

    #[test]
    fn limb_witness_outputs_preserve_zero_maximum_and_distinct_words() {
        // SYSCOIN: Exercise all formerly uninitialized integer arrays at both
        // word boundaries and with asymmetric limbs to detect ordering changes.
        macro_rules! check {
            ($gadget:ident, $length:expr, $decompose:ident) => {
                for pattern in 0..3 {
                    let words: [u32; $length] = std::array::from_fn(|i| match pattern {
                        0 => 0,
                        1 => u32::MAX,
                        _ => 0x1234_0000 + i as u32 * 0x101,
                    });
                    let fields = words.map(|word| F::from_u64_unchecked(u64::from(word)));
                    let witness =
                        <$gadget<F> as CSAllocatableExt<F>>::witness_from_set_of_values(fields);
                    assert_eq!($decompose(witness), words);
                }
            };
        }
        check!(UInt160, 5, decompose_address_as_u32x5);
        check!(UInt256, 8, decompose_u256_as_u32x8);
        check!(UInt512, 16, decompose_u512_as_u32x16);
    }
}
