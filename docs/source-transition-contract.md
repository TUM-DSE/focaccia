# Shared source-transition validation

The Intel live validator defaults to source-derived symbolic residuals through
Focaccia's shared transformation, composition, prediction and comparison core.
The full BusyBox software-SHA workload and its corruption controls have passed
through this path. The legacy concrete evaluator remains available only through
`--concrete-diagnostic`; its earlier SHA result is not symbolic acceptance evidence.

## Shared infrastructure

`SymbolicTransform` and `SymbolicTransformComposer` support source-owned
transformations preserving:

- symbolic definedness masks, including mask-only state changes;
- source guards rewritten at each composition prefix;
- ordered, conditional memory writes and address/value definedness;
- bounded deferred reads referring to explicit prior-write prefixes;
- source metadata across concatenation and serialization.

`source_owned=True` bypasses the legacy handwritten x86 undefined-flag heuristic
and requires explicit output masks. Synthetic knownness inputs are constructed
with `knownness_symbol(base_register, width)` and supplied separately from
hardware register observations. They must not be captured as hardware registers.

Legacy unmasked evaluation APIs reject source-owned transformations. The shared
`boundary_oracle.predict` uses `eval_source_transition` to evaluate registers,
masks and ordered stores in one checked context. Guards must hold and active
store addresses/values must be fully defined. Inactive conditional effects do
not force address/value evaluation. Unsupported definedness propagation fails
closed. The requested observation view includes unchanged registers, so unexpected
clobbers are checked too.

Evaluation caches belong to one fixed prestate, knownness input and write history;
write-prefix-sensitive definedness is keyed by its prefix. They are not reused
across guest boundaries. Composer forks and source projections share immutable
expression nodes without modifying the original prefix. This avoids repeatedly
composing REP prefixes without dropping the final transition's guards or effects.
The Intel adapter also retains and checks source read effects whose values become
dead during composition, including their conditions, address masks and permissions.

`boundary_oracle.compare` separates required-known policy from observation masks.
It can require independently observed byte-level store coverage and rejects
absent, extra or missing store evidence. Permission capture, boundary identity,
coherent observations and syscall contracts remain adapter duties.

The ARM online probe uses this shared prediction core on its non-iterative path
and the shared comparison core. Its existing iterative/native reduction modes
remain optional ARM-specific paths. This does not add a claim of passive-store
coverage to ARM runs that did not collect it.

## Source compiler and adapter boundary

TIR specializes exact XED-bound instruction functions with its existing generic
partial evaluator and exports schema-2 residuals. Focaccia imports their expression
DAGs into the shared symbolic core. There is no concrete opcode evaluator or
Miasm instruction-semantics fallback. The earlier experimental ADD exporter was
not promoted into a second partial evaluator.

XED decoding, the qualified Intel CPU profile, QEMU observation, memory permissions,
syscall ABI and terminal handling remain architecture-specific. Published source
instruction bodies remain unchanged; approved missing definitions and user-mode
bindings remain explicit in the model provenance. This is qualified single-threaded
Linux-user validation, not full-system Intel coverage. Private source models and
residual dumps remain outside Git.

## End-to-end acceptance

The accepted symbolic report is
`/tmp/intel-symbolic-live-report-20261019-finaloracle.json`, with its
`.evidence.jsonl` companion. It records:

- 3,064 validated translation blocks, 16,998 instructions and 17,024 source steps;
- all 3,115 event intervals covered by store-footprint checks;
- 10,344 checked write bytes;
- the expected SHA-256 digest
  `713784ad24639a95b1c764f5cced9985c72fff472df3c4650e8ac8f05f4cc922`;
- validated `exit_group` status 0;
- rejection of wrong RIP, unexpected stores, syscall RBX/XMM0 clobbers and
  wrong resumed syscall PC.

Predictions use pre-boundary input state and source semantics. Post-state and
actual-store observations are comparison evidence, never expected-value inputs.
QEMU retains optimized translation-block execution; no per-instruction execution
callbacks were added. Earlier partial runs and the old concrete run are not used
to establish this acceptance.
