use super::{BoolsBuffer, CircuitTranscript};
use crate::config::DevCSConfig;
use crate::cs::cs_builder::new_builder;
use crate::cs::cs_builder_reference::CsReferenceImplementationBuilder;
use crate::cs::gates::{
    BooleanConstraintGate, ConstantsAllocatorGate, FmaGateInBaseFieldWithoutConstant, NopGate,
    ReductionGate,
};
use crate::cs::implementations::reference_cs::CSReferenceAssembly;
use crate::cs::traits::cs::ConstraintSystem;
use crate::cs::traits::gate::GatePlacementStrategy;
use crate::cs::CSGeometry;
use crate::dag::CircuitResolverOpts;
use crate::field::goldilocks::GoldilocksField as F;
use crate::field::U64Representable;
use crate::gadgets::num::Num;
use crate::gadgets::traits::allocatable::CSAllocatable;
use crate::gadgets::traits::witnessable::WitnessHookable;
use crate::worker::Worker;
use std::alloc::Global;

type Assembly = CSReferenceAssembly<F, F, DevCSConfig, Global>;

#[derive(Clone, Debug)]
struct FixedTranscript(F);

impl CircuitTranscript<F> for FixedTranscript {
    type CircuitCompatibleCap = ();
    type TransciptParameters = F;
    fn new<CS: ConstraintSystem<F>>(_cs: &mut CS, value: F) -> Self {
        Self(value)
    }
    fn witness_field_elements<CS: ConstraintSystem<F>>(&mut self, _cs: &mut CS, _els: &[Num<F>]) {}
    fn witness_merkle_tree_cap<CS: ConstraintSystem<F>>(&mut self, _cs: &mut CS, _cap: &[()]) {}
    fn get_challenge<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) -> Num<F> {
        Num::allocated_constant(cs, self.0)
    }
}

fn query_witness(
    challenge: u64,
) -> (u64, Assembly) {
    let geometry = CSGeometry {
        num_columns_under_copy_permutation: 136,
        num_witness_columns: 5,
        num_constant_columns: 4,
        max_allowed_constraint_degree: 8,
    };
    let builder = new_builder::<_, F>(CsReferenceImplementationBuilder::<
        F,
        F,
        DevCSConfig,
    >::new(geometry, 1024));
    let builder = ConstantsAllocatorGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = BooleanConstraintGate::configure_builder(
        builder,
        GatePlacementStrategy::UseSpecializedColumns {
            num_repetitions: 1,
            share_constants: false,
        },
    );
    let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = ReductionGate::<F, 4>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder =
        NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
    let mut cs = builder.build(CircuitResolverOpts::new(1 << 16));
    let mut transcript = FixedTranscript(F::from_u64_unchecked(challenge));
    let mut buffer = BoolsBuffer {
        available: vec![],
        max_needed: 21,
    };
    let bits = buffer.get_bits(&mut cs, &mut transcript, 21);
    let index = bits.iter().enumerate().fold(0, |result, (i, bit)| {
        result | ((bit.witness_hook(&cs)().unwrap() as u64) << i)
    });
    cs.pad_and_shrink();
    (index, cs.into_assembly::<Global>())
}

#[test]
fn canonical_query_bits_accept_boundaries_and_match_native_indices() {
    for challenge in [
        0,
        1,
        (1 << 32) - 2,
        (1 << 32) - 1,
        1 << 32,
        0xfffffffeffffffff,
        F::ORDER - 1,
    ] {
        let (index, mut assembly) = query_witness(challenge);
        assert_eq!(index, challenge & ((1 << 21) - 1));
        assert!(assembly.check_if_satisfied(&Worker::new_with_num_threads(1)));
    }
}
