# Focaccia

This repository contains the source code for Focaccia, a comprehensive validator for CPU emulators
and binary translators.

## License

Focaccia is distributed under the BSD 3-Clause license. See [`LICENSE`](LICENSE).

## Requirements

Python dependencies are handled via pyproject and uv. We provide first-class support for Nix via our
flake, which integrates with our Python uv environment via uv2nix. 

We do not support any other build system officially but Focaccia has been known to work on various
other systems also, as long as its Python dependencies are provided.

For development, the checked-in `.envrc` enters the flake's default development
shell through nix-direnv. From a checkout with direnv and nix-direnv installed,
authorize it once:

```bash
direnv allow
```

Using `nix develop` directly remains equivalent.

### TIR backend development

The `tir` flake input tracks the `carbonara` branch of `TUM-DSE/airlift` on
GitHub using SSH (`git+ssh://git@github.com/TUM-DSE/airlift.git?ref=carbonara&shallow=1`);
`flake.lock` pins the exact revision and its build dependencies. Fetching requires
SSH access to that repository, but no sibling TIR checkout is needed.
Update this dependency deliberately with `nix flake update tir`.

```bash
nix build .                     # default Focaccia, without TIR build dependencies
nix build .#focaccia-tir         # opt-in Focaccia package with the TIR oracle
nix develop .#tir                # editable Focaccia + Rust/LLVM + packaged TIR data
nix build .#tir-oracle            # specification-derived instruction oracle
nix build .#tir-translator        # installed translator and inspection tools
nix build .#tir-asl-specification # generated AST and provenance manifest
nix develop .#tir -c tiramisu-translate --help
nix run .#tir-oracle -- 4194304 420400f1 # SUBS X2, X2, #1 at 0x400000
```

The `focaccia`/default package does not build or depend on TIR. The separate
`focaccia-tir` output includes the oracle and configures its path for
`bin/capture-transforms`; the optional development shell also provides the
packaged AST, x86-64 runtime archive, and linker. Capture selects semantics with
`--semantics-backend miasm|tir`; Miasm remains the default. For example, use
`nix develop .#tir -c capture-transforms --help` to inspect the capture options.
Native capture still requires its usual debugger/RR permissions.

The opt-in TIR backend has a closed-world allowlist for the AArch64
instruction classes dynamically reached by the static-musl issue #2248, #364,
and #2419 fixtures. It covers branches, integer/address construction, scalar
and vector memory forms, vector DUP, system-register access, the arithmetic
witness, LDAPUR, and LDSMAXB. Audited representative opcodes are committed in
the fixtures' `instruction-classes.json` files; the two added classes are
restricted to exact measured trigger opcodes before they enter the whole-program
runs. A Focaccia-owned Rust
helper uses the pinned ASL frontend and specializer, then exports each residual
computation into Focaccia's existing symbolic-expression representation. It
does not invoke LLVM or Miasm instruction semantics. Miasm remains only the
disassembler and shared expression representation.

Build Rust-helper changes with `nix build .#tir-oracle`. Nix places the helper
in the fetched TIR workspace and resolves its lockfile offline using only the
crate versions vendored from TIR's pinned `Cargo.lock`; the helper's relative
Cargo paths are for that assembled workspace, not a sibling checkout.

The typed specification is prepared once by Nix. The helper derives each
instruction transformation with runtime registers left symbolic. Its allowlist
is deliberately exact; unsupported classes or residual operations fail closed.
SVC is classified but remains an explicit external-action boundary: the live
harness models only the fixture's controlled set_tid_address and terminal
exit_group actions. There is no Miasm fallback.
`FOCACCIA_TIR_ORACLE` can select the helper executable.

The dedicated `checks.<system>.tir-oracle-validation` exercises real
specification-derived arithmetic through evaluation, composition, serialization,
and mismatch detection. `checks.<system>.instruction-semantic-backends` covers
backend selection, protocol failures, and fake-target capture/gap behavior.
These checks need neither RR nor native debugger attachment. They do not claim
that native TIR-backed application capture has been exercised.
`checks.<system>.default-without-tir` checks the default package's runtime closure,
and `checks.<system>.focaccia-tir-package` exercises the opt-in package.
`nix run .#check-default-without-tir` additionally checks the full transitive build
graph without building every compiler and source archive in that graph.
A full `nix flake check` includes optional TIR checks; an ordinary `nix build`
only builds the default package.

`checks.<system>.tir-package-contract` verifies that the Python environment can
use the installed tools and that the AST matches its manifest.
`checks.<system>.tir-packaged-translation` translates and executes a small guest
using the pinned package, without RR or native debugger attachment. Both checks
are available on `aarch64-linux` and `x86_64-linux`.

### Live TIR/QEMU validation without record/replay

```bash
nix run .#tir-no-replay-smoke -- --run-directory "$PWD/tir-2248"
nix run .#tir-issue-364-online -- --run-directory "$PWD/tir-364"
nix run .#tir-issue-2419-online -- --run-directory "$PWD/tir-2419"
# Sandboxed checks retain all evidence in their Nix outputs:
nix build .#checks.aarch64-linux.tir-no-replay-e2e
nix build .#checks.aarch64-linux.tir-issue-364-e2e
nix build .#checks.aarch64-linux.tir-issue-2419-e2e
nix build .#checks.aarch64-linux.tir-aarch64-evaluation-matrix
```

Each fixture preserves its canonical trigger values and makes the historical
result observable as its natural exit status, while avoiding unrelated output
syscalls. #2248 uses `callme(0,0,0,1,2)`. #364 applies `LDSMAXB` to the canonical
`{0,-1,3}` values. #2419 loads the canonical `0x11111111deadbeef` through a
`-8` LDAPUR offset and places a distinct mapped canary at the historically
misdecoded `+504` address. All are static-musl ET_EXEC files, run with empty
argv additions, an empty environment, and explicit `max,sve=off`. The oracle
covers every dynamic instruction from ELF entry to the live exit_group SVC.

The unversioned lockstep plugin wire format binds executable, argv, environment,
and CPU manifests. In online mode it emits every executed translation block as
a contiguous ordered-PC descriptor plus global syscall entry/return events. It
installs no instruction or memory callbacks that could inhibit TCG optimization.
The validator resolves each descriptor only against executable bytes in the
immutable, hash-bound ELF. On the block's first execution it lazily asks TIR for
missing instruction transformations, caches both instruction specializations
and composed blocks, evaluates the composed semantics at the live source state,
and compares at the next TB or external-action boundary. TIR's ordered stores
remain ordered evidence, while their final write ranges are read and checked at
the next boundary. Interior set_tid_address is bound to the plugin process
identity.

Fixed QEMU naturally exits 0 and is accepted with complete whole-program and
terminal evidence. Each narrowly regression-injected QEMU naturally exits 1;
its own single execution exposes its actual blocks online. #2248 and #2419 each
report exactly one confirmed `X0` mismatch. #364 reports exactly one confirmed
final-memory mismatch (`03` expected, `ff` actual). Each case launches QEMU
exactly once. There is no preliminary discovery execution, precomputed dynamic
path oracle, debugger stepping, ptrace, RR, Miasm semantics, synthetic guest
mutation, or per-instruction optimizer barrier. Unsupported instructions,
non-ELF block bytes, event gaps, unmatched stores/actions, and incomplete
terminal evidence fail closed.

For #364, TIR emits one LDSMAXB architectural state transition: the returned old
byte and the conditional signed-maximum write both consume the same incoming
memory state. The single-thread fixture validates the resulting register and
final byte at the next TB boundary; it does not model the operation as an
unrelated load and store and makes no multi-thread ordering claim. For #2419,
the claim is the signed effective address and eight little-endian data bytes,
not acquire ordering.

| Trigger | Current fixed QEMU | Injected historical regression | Terminal result |
| --- | --- | --- | --- |
| #2248 | accepted | one confirmed `X0` mismatch | 0 / 1 |
| #364 LDSMAXB | accepted | one confirmed memory mismatch (`03` / `ff`) | 0 / 1 |
| #2419 LDAPUR | accepted | one confirmed `X0` mismatch (target / `+504` canary) | 0 / 1 |

The matrix check writes machine-readable `result-matrix.json`; every row records
`qemu_executions: 1` and complete terminal evidence.

The run directory retains source and binary identities, exact commands, ordered
block/store/syscall evidence, cache statistics, terminal evidence, and reports.
`result.json` summarizes the two cases. The default Focaccia build remains
TIR-free; this app and its check are explicit opt-ins.

## How To Use

`focaccia` is the main executable. Invoke `focaccia --help` to see what you can do with it.

### QEMU

A number of additional tools are included to simplify use when validating QEMU:
`capture-transforms`, `convert-log`, `validate-qemu`, `validation_server`. They enable the following workflow.

```bash
nix run .#capture-transforms -- -o oracle.trace ./bug.out
nix run .#qemu-x86_64 -- -g 12345 ./bug.out &
nix run .#validate-qemu -- --symb-trace oracle.trace --remote localhost:12345
```

Focaccia does not collect or print benchmark timings during normal operation. Evaluation harnesses
that need native component measurements can explicitly pass `--profile-report profile.json` to
`capture-transforms`; the resulting plain JSON file contains concrete, symbolic, validation, total
trace, and serialization durations. Trace and serialization wall times are reported separately so
persistence cost is not included in the measured trace runtime.

The above workflow works for reproducing most QEMU bugs but cannot handle the following two cases:

1. Optimization bugs

2. Bugs in non-deterministic programs

We provide alternative approaches for optimization bugs and a bounded, fail-closed x86-64 replay
path for selected RR-recorded effects. That replay path is narrower than general non-deterministic
program support.

Concurrent validation is not supported. The historical scheduler source is preserved under
`focaccia.experimental` for possible redesign, but it has no CLI or flake entry point and is not part
of the supported QEMU validation path.

### QEMU Optimization bugs 

When a bug is suspected to be an optimization bug, you can use the Focaccia QEMU plugin. The QEMU
plugin is exposed, along with the QEMU version corresponding to it, under the qemu-plugin package in
the Nix flake.

It is used as follows:

```bash
nix run .#validate-qemu -- --symb-trace oracle.trace --use-socket=/tmp/focaccia.sock --guest-arch=arch
```

Once the server prints `Listening for QEMU Plugin connection at /tmp/focaccia.sock...`, QEMU can be
started in debug mode:

```bash
qemu-<arch> [-one-insn-per-tb] --plugin result/lib/plugins/libfocaccia.so bug.out
```

Note: the above workflow assumes that you used `nix build .#qemu-plugin` to build the plugin under
`result`.

Using this workflow, Focaccia can determine whether a mistranslation occured in that particular QEMU run.

Focaccia includes support for tracing non-deterministic programs using the RR debugger, requiring a
similar workflow:

```bash
nix run .#rr -- record -n -o bug.rr.out ./bug.out
nix run .#rr -- replay -s 12345 bug.rr.out
nix run .#capture-transforms -- \
  --remote localhost:12345 --deterministic-log bug.rr.out \
  -o oracle.trace ./bug.out
```

Note: the `rr replay` call prints the correct binary name to use when invoking `capture-transforms`,
it also prints program output. As such, it should be invoked separately as a foreground process.

Note: `rr record` may fail on Zen and Zen+ AMD CPUs. It is generally possible to continue using it
by specifying flag `-F` but keep in mind that replaying may fail unexpectedly sometimes on such
CPUs.

The project now has fixture-backed, fail-closed **x86-64 and AArch64
single-thread replay engines** for this workflow. Every encountered syscall/RR
effect is classified as recorded replay, execute-and-reconcile, narrowly safe
passthrough, or rejection; an unclassified call is never executed on the live
host. Both engines cover bounded direct and `iovec` outputs, virtual
descriptors, common file/socket effects, anonymous mapping reconciliation, and
terminal calls. Both engines validate Linux signal frames, replay recorded
handler-entry FP/vector state through a typed backend boundary, and have fixture
models of `rt_sigreturn`; AArch64 coverage is limited to the base FPSIMD context
and rejects SVE/SME extension records. Variant-dependent `ioctl`, nested
`recvmsg`/descriptor passing, file-backed mappings, task creation,
interrupted-syscall restart, and unknown RR events are rejected. Live GDB
signal-handler delivery on both ISAs also rejects before mutation because the
current QEMU remote backend cannot atomically establish the complete recorded
extra-register state.

The flake exposes RR 5.8.0 on both x86-64 and AArch64. This version is
intentional: RR 5.9's standalone `replay -s` path forces GDB protocol behavior
even when an external LLDB client connects, while Focaccia's native tracer is
an LLDB client. RR 5.8 retains trace schema/version 85 and does not contain that
standalone-server regression. Native AArch64 recording requires an RR-supported
microarchitecture such as Arm Neoverse. The `qemu-x86_64` app and the bounded
smoke harness use a static, non-PIE, single-thread x86-64
`openat`/`read`/`write`/`close` fixture. Inspect that harness's exact plan without
launching a target:

```bash
nix run .#rr-qemu-smoke -- \
  --run-directory "$PWD/focaccia-smoke" --dry-run
```

On a separately approved native x86-64 tracing runner, omit `--dry-run` to run
the bounded workflow. The output directory retains the exact command plan,
RR trace, symbolic oracle, content-bound run manifest, logs, structured
validation/replay-coverage report, and final result. Existing directories are
never overwritten. `validate-qemu --report FILE` also persists structured
coverage for a manual GDB validation; `--run-manifest` plus repeated
`--run-input NAME=PATH` verifies producer/consumer identities before connecting
to QEMU.

This harness has not yet been executed as an authoritative project check, so it
is not an end-to-end support claim. Its x86 fixture build check and the live
smoke run remain pending on the designated native x86-64 runner. Native
AArch64 RR record/replay is exposed for oracle capture, and its QEMU-side
syscall replay baseline is covered by synthetic RR/fake-target checks. No live
AArch64 RR-to-QEMU run has passed, so this is not an end-to-end AArch64 support
claim. Live signal-handler delivery, AArch64 SVE/SME signal contexts, concurrent
replay, and general application replay remain unsupported.

### Box64

For validating Box64, we create the oracle and test traces and compare them
using the main executable.

```bash
capture-transforms -o oracle.trace bug.out
BOX64_TRACE_FILE=test.trace box64 bug.out
focaccia -o oracle.trace --symbolic -t test.trace --test-trace-type box64 --error-level error
```

## Tools

The `tools/` directory contains additional utility scripts to work with focaccia.

 - `convert.py`: Convert logs from QEMU or Arancini to focaccia's snapshot log format.

## Project Overview (for developers)

### Snapshots and comparison

The following files belong to a rough framework for the snapshot comparison engine:

 - `focaccia/snapshot.py`: Structures used to work with snapshots. The `ProgramState` class is our
                           primary representation of program snapshots.

 - `focaccia/compare.py`: The central algorithms that work on snapshots.

 - `focaccia/arch/`: Abstractions over different processor architectures. Currently we have x86 and
                     aarch64.

### Concolic execution

The following files belong to a prototype of a data-dependency generator based on symbolic
execution:

 - `focaccia/symbolic.py`: Algorithms and data structures to compute and manipulate symbolic program
                           transformations. This handles the symbolic part of "concolic" execution.

 - `focaccia/lldb_target.py`: Tools for executing a program concretely and tracking its execution
                              using [LLDB](https://lldb.llvm.org/). This handles the concrete part
                              of "concolic" execution.

 - `focaccia/miasm_util.py`: Tools to evaluate Miasm's symbolic expressions based on a concrete
                             state. Ties the symbolic and concrete parts together into "concolic"
                             execution.

### Helpers

 - `focaccia/parser.py`: Utilities for parsing logs from Arancini and QEMU, as well as
                         serializing/deserializing to/from our own log format.

 - `focaccia/match.py`: Algorithms for trace matching.

### Supporting new architectures

To add support for an architecture <arch>, do the following:

 - Add a file `focaccia/arch/<arch>.py`. This module declares the architecture's description, such
   as register names and an architecture class. The convention is to declare state flags (e.g. flags
   in RFLAGS for x86) as separate registers.

 - Add the class to the `supported_architectures` dict in `focaccia/arch/__init__.py`.

 - Depending on Miasm's support for <arch>, add register name aliases to the
   `MiasmSymbolResolver.miasm_flag_aliases` dict in `focaccia/miasm_util.py`.

 - Depending on the existence of a flags register in <arch>, implement conversion from the flags
   register's value to values of single logical flags (e.g. implement the operation `RFLAGS['OF']`)
   in the respective concrete targets (LLDB, GDB, ...).

