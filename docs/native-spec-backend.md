# Native hardware checked against specification semantics

`validate-native-spec` uses native execution as an observation backend, not as
an oracle. ARM predictions come from the existing TIR specification bridge;
Intel predictions come from source-derived Intel symbolic residuals, or from
the explicitly selected Sail x86 specification backend. All sources use the
shared symbolic transformation and boundary-comparison machinery. There
is no fallback to Miasm instruction semantics or a second native execution used
as an expected result.

## Execution and evidence

The initial backend targets Linux, static little-endian AArch64 and x86-64 ELF
programs, and single-threaded execution from the ELF entry through a validated
terminal syscall. It reuses the native LLDB target and observes instruction
boundaries. This does not change QEMU's optimized translation-block execution.

At a boundary, the validator freezes registers, mappings and stable private
memory before predicting the next transition. Observations made after execution
are used for comparison, never to construct expected register or memory values.
The ARM comparison view includes GPRs, SP/PC, SIMD registers, TLS, FPCR/FPSR
and NZCV. Other raw PSTATE bits, including debugger single-step state, are not
claimed as modeled architectural outputs. Raw observations are not rewritten to
make specification guards pass. Intel uses the existing qualified GPR, RIP,
RFLAGS-definedness, XMM and TLS view, not an unvalidated x87/AVX extension.

Syscalls are explicit environment boundaries with architecture-specific ABI,
output-memory and resume obligations, not specification implementations of Linux.
Unsupported instructions, syscalls, signals, threads or observation gaps must
fail closed rather than turn into a successful partial run. Read-only file paths
must be explicitly qualified; writes are limited to captured stdout/stderr.
Mapping changes are bounded and tracked. The initial Linux policy requires
4-KiB pages and rejects readability-changing `mprotect` calls rather than
pretending to validate hidden memory contents. These limits do not authorize
arbitrary filesystem writes or credential changes.

### Memory capability is deliberately different from QEMU

Native memory evidence is a complete boundary diff of the supported private
memory mappings, alongside permission checks for source accesses. It checks
unexpected changed bytes as well as the source-predicted writes. Kernel-owned
volatile mappings are outside this stable-private-memory scope.

This is **not an actual-store trace**. A store that writes the same value, or
multiple stores whose intermediate effects cancel between observations, cannot
be reconstructed from snapshots. Reports must identify the memory evidence as
private-memory boundary differences and must not claim QEMU's passive byte-level
store-footprint coverage. Shared writable memory, concurrent execution and MMIO
are outside this contract.

## Hardware configuration is an input, not an instruction result

The QEMU ARM profile pins `DCZID_EL0` to its configured cache-zero block size.
Native hardware can differ. Before executing the guest, the native target pins
its owned process to one CPU and runs an independent native configuration helper
on that same CPU. The observed `DCZID_EL0` configures the existing TIR partial
evaluator; both `MRS` and `DC ZVA` are still predicted from their specification
bodies. Its DZP bit supplies the effective EL0 permission contract: within the
existing no-EL2 source profile, DZE is enabled only when DZP reports that cache
zeroing is permitted. This is a permission-compatible source configuration, not
a claim that the privileged host SCTLR register was directly read. Prohibited
zeroing and reserved block-size encodings fail closed. The architectural field
contract is documented in the [DCZID_EL0 register reference](https://www.df.lth.se/~getz/ARM/SysReg/AArch64-dczid_el0.html). The helper identity and CPU/configuration evidence belong in the report.
The destination value of the guest's `MRS` is never used to supply its own expected
result. Native-configured residuals have a distinct profile contract; the default
QEMU decoder must not silently accept them.

The owned-process timeout uses a Linux pidfd, so it can interrupt a debugger step
blocked in a syscall without targeting a subsequently reused PID. For Intel REP,
the execution adapter coalesces same-PC debugger iteration stops into a complete
architectural-instruction boundary. The full specification prediction is computed
before execution; observed PC is used only to identify the execution boundary,
not to select an expected result.

## Running

The Nix entry point supplies the pinned ARM specification oracle:

```sh
nix run .#validate-native-spec -- --help
```

`nix run .#validate-native-sail -- --help` selects the public Sail source and
its pinned exporter/model. Its qualified coverage and fail-closed limits are
specified in `docs/sail-spec-backend.md`; it is not full-application acceptance.

The Intel source selection additionally requires the Intel oracle executable,
XED decoder and private source model. Private Intel material is not bundled or committed. Hardware runs
must match the host architecture; an emulated foreign-architecture run is not
native acceptance.

## Acceptance policy

A whole-program success requires verified entry, all intervening boundaries,
syscall preservation and resume checks, and an observed terminal outcome. Known
workloads additionally require their independent expected stdout and exit status.
Corrupted PC, unchanged-register clobber, memory changes and syscall/resume
observations must be rejected by the same validation path.

The current acceptance host is AArch64. The existing ARM regression programs
passed from entry to normal exit with matching stdout: #2248 (1,138 instruction
boundaries), #364 (1,189), and #2419 (1,336). Real-observer corruption controls
rejected wrong PC, unchanged GPR/SIMD clobbers, FPSR changes, unexpected changed
RAM, syscall X8 clobbers and wrong resumed PC. Reports are retained under
`/tmp/carbonara-native-arm-sail-regression-{2248,364,2419,controls}.json`.
These reruns use ARM TIR revision `99f4b3be1db27a024c4b2b8adf6c4e21a7733e27`.

The exploratory Lua run is not accepted. Exclusive-access regions now execute
uninterrupted between checked exits, matching alternatives predicted from the
source before execution. A named vDSO clock service has a bounded environmental
contract, not an instruction-level proof of vDSO internals. The latest retained
run checked 79,520 instruction boundaries, ten exclusive regions and one vDSO
service before rejecting unsupported floating-point unary semantics at
`0x41e738` (`/tmp/carbonara-lua-native-fmov.json`). No auxiliary-vector or launch
profile change was made. Region observations do not claim an internal-PC trace.

Native Intel implementation and synthetic source-model tests do not constitute
Intel hardware acceptance; that remains pending until an authorized x86-64 host
is available. Unsupported larger workloads remain explicitly unqualified; a
partial run cannot be reported as whole-program acceptance.
