# Sail x86 specification backend

Sail x86 is an additional specification source, not an alternative observation
backend or a second concrete instruction implementation. Its source step is
parsed, typechecked, specialized by TIR's strict source entry point, and exported
by the same Rust expression evaluator used by the ARM bridge. Python imports
its values, source masks, guards and ordered effects into the existing x86
residual carrier, `SymbolicTransform`, composer, predictor and comparator.
The existing `SymbolicIntelLiveModel` TB predictor also consumes
`SailSymbolicBackend` directly; its historical class name does not select Intel
instruction behavior. Real-model tests exercise this path, not a substitute TB
engine. There is no Miasm/concrete-opcode fallback and no poststate oracle input.

## Nix entry points

- `sail-x86-specification`: pinned Sail model and patched plugin/compiler;
  generated `x86.tir`, content hash and provenance live in the Nix store.
- `sail-oracle`: shared exporter built against the merged `tir/carbonara`
  frontend, with real-model Rust tests enabled during the build.
- `validate-native-sail`: selects Sail explicitly in `validate-native-spec`
  and supplies the pinned model and exporter.
- `checks.<system>.sail-source-validation`: mandatory source-backed Python
  adapter/composition/corruption tests; both oracle and model are supplied, so
  the optional local-test skip cannot mask missing integration.

For example, on AArch64:

```sh
nix build .#sail-oracle .#sail-x86-specification
nix build .#checks.aarch64-linux.sail-source-validation
nix run .#validate-native-sail -- --help
```

Both Linux systems expose these derivations. Building/testing on AArch64 does
not establish x86 hardware acceptance. The native runner refuses a Sail x86
selection for an ARM target; it does not silently select ARM instead.

The merged TIR branch does not expose the older optional ARM oracle-JIT APIs.
The `arm-tir` input therefore separately pins their validated source revision;
`tir` pins the merged Sail frontend. Both compile the shared Rust exporter and
feed the same Python symbolic pipeline. This preserves ARM kernels rather than
disabling their checks or falling back to concrete semantics. Reports use the
actual source revision for each package, not a common mislabeled revision.

## Source and configuration obligations

Every response binds exact request PC/code bytes, source-certified instruction
length, profile, parsed-model SHA256 and TIR revision. Successful responses
certify a complete source step with explicit zero repeat/environment-cutpoint
controls in the shared x86 vocabulary; the importer rejects micro-step or OS
handoff controls outside this profile. Revision drift, unknown
fields, missing masks and future/self write-prefix references are rejected.
The model must have matching adjacent provenance declaring the preserved
`sail_undefined_v1` representation. Raw zero-lowered models are rejected.

Undefined scalar values remain opaque through specialization. The exporter
projects them with source-definedness masks; observing hardware bytes never
makes an undefined source bit known. Active stores with any undefined value or
address bit are rejected by the shared predictor before execution. Whole-vector
undefined generation aborts instead of manufacturing correlations between lanes.

The strict specialization API preserves address/compliance checks and keeps
host-backed x87 operations opaque, even when their operands are constants.
Unsupported x87 helpers are rejected by the exporter, never executed to supply
hardware expectations. Observable RFLAGS configuration pins are converted into
prestate value/knownness guards derived from the selected source profile. The
current profile requires `(RFLAGS & 0x3d7300) == 0x200`; arithmetic flags and DF
remain symbolic. This is a qualified user-mode model, not a claim of arbitrary
privileged-machine or CPU-feature conformance.

Unused source reads retain permission/definedness obligations. Stores remain an
ordered list, including duplicate destinations. The decoder enforces the write
prefix available to every effect. Source RIP must be fully defined before native
execution; corrupted or undefined control cannot select an expected path from
hardware results.

## Verified scope and limits

The real-model checks cover ADD (including carry/overflow/flag values), XOR
(including undefined AF), load, store, direct and conditional branch control,
and store-to-load block composition through both the common composer and live
TB predictor. XOR followed by LAHF verifies that undefined AF stays unknown in
the next instruction's register result rather than becoming an observed fact.
They exercise the shared comparator's rejection of wrong PC, unchanged-register
clobber and unexpected RAM changes. Negative checks cover profile mismatch,
undefined control, denied memory, malformed provenance/identity/masks and
unsupported helpers. These are source-backed adapter tests with synthetic
independent prestates, not x86 native hardware acceptance.

The Nix gate runs these real-model tests without skips, plus Ruff and targeted
Pyright checks for the new source adapter. The broader repository's Pyright
baseline remains 89 existing diagnostics: a clean HEAD audit and the completed
integration both report the same 89, with no new diagnostics. This is not a
claim that the repository-wide typecheck is green.

This is not a full-ISA or whole-application acceptance claim. Syscalls, x87,
unrepresentable state and read-after-write within a single source instruction
are currently unsupported. Such a boundary fails before native execution;
there is no successful partial whole-program result. Cross-instruction memory
composition uses the existing composer. Hardware acceptance requires an x86-64
host and a workload wholly inside the supported source/OS-service contracts.

Native observations retain the existing full-private-memory boundary-diff
capability. They are not an actual-store trace: same-value stores and cancelling
intermediate writes are not observable. QEMU's optimized TB execution is not
changed by adding this specification source.
