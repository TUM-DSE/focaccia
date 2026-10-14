# Shared source-transition validation (convergence in progress)

The Intel live application still uses `tests/probes/intel_live_validate.py` and
its concrete TIR evaluator path. It has **not** yet been replaced by the ARM-style
symbolic pipeline. The completed SHA report from the previous milestone does
not validate this new integration.

## Shared infrastructure

`SymbolicTransform` and `SymbolicTransformComposer` now accept source-owned
transformations. These preserve:

- symbolic definedness masks, including mask-only state changes;
- source guards rewritten at each composition prefix;
- ordered memory writes and their address/value definedness;
- source metadata across concatenation and serialization.

`source_owned=True` bypasses the legacy handwritten x86 undefined-flag heuristic.
It requires explicit output masks. Synthetic knownness inputs are constructed
with `knownness_symbol(base_register, width)` and supplied separately from
hardware register observations. They must not be captured as hardware registers.

Legacy unmasked evaluation APIs reject source-owned transformations. Use
`eval_validation_register_transforms_with_masks` and
`eval_source_ordered_memory_transforms`, or the shared `boundary_oracle.predict`
entry point. Guards must hold and store addresses/values must be fully defined.
Unsupported definedness propagation fails closed.

`boundary_oracle.compare` separates the required-known policy from observation
masks. It can require independently observed byte-level store coverage, and
rejects absent, extra, or missing store evidence. Permission capture, boundary
identity, coherent observations, and syscall contracts remain adapter duties.

The ARM online probe now uses this shared prediction core on its non-iterative
path and the shared comparison core. Its existing iterative/native reduction
paths are retained. This refactor does not add a claim of passive-store coverage
to ARM runs that did not collect it.

## Demonstrated source bridge

A local experimental cross-language test exported Intel's ADD operation as
symbolic scalar expressions, decoded them using the shared expression decoder,
evaluated multiple fresh operand assignments, checked arithmetic flags and source
guards, and composed two source-owned transformations using Focaccia's existing
composer. The experimental exporter is **not included in this change**: it did
not establish reliable full-instruction specialization. Its code and test are
archived locally under `/tmp/carbonara-convergence-experiment/` rather than added
as another production partial evaluator.

This is an **operation-level** test, not decoded-instruction or application
acceptance. It does not establish full-model profile specialization, memory
binding, syscall handling, or all 156 workload forms in the new path.

The next compiler integration should use TIR's generic
`specialize_typed_function` entry point, backed by the existing specializer,
rather than duplicate its partial-evaluation logic. The shared decoder accepts
profile-supplied register contracts and signed scalar operators needed by that
integration. Source-derived initialization, memory bindings, definedness, and
ordered effect extraction still need to be connected to the full Intel model.

The full application must be rerun through the converged path with the existing
PC, store, syscall-preservation, and resumed-PC negative controls before the
standalone Intel path can be retired.
