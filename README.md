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
nix develop .#tir                # editable Focaccia + Rust/LLVM + packaged TIR data
nix build .#tir-oracle            # specification-derived instruction oracle
nix build .#tir-translator        # installed translator and inspection tools
nix build .#tir-asl-specification # generated AST and provenance manifest
nix develop .#tir -c tiramisu-translate --help
nix run .#tir-oracle -- 4194304 420400f1 # SUBS X2, X2, #1 at 0x400000
```

The opt-in shell provides the packaged AST, x86-64 runtime archive, linker, and
`focaccia-tir-oracle`. Capture selects instruction semantics with
`--semantics-backend miasm|tir`; Miasm remains the default. For example, use
`nix develop .#tir -c capture-transforms --help` to inspect the capture options.
Native capture still requires its usual debugger/RR permissions.

The initial TIR backend supports the AArch64 **ADD/ADDS/SUB/SUBS immediate**
instruction class in little-endian, user-mode configuration, including 32-bit
writes, stack-pointer operands, and NZCV flags. A Focaccia-owned Rust helper uses
the pinned ASL frontend and specializer, then exports the residual computation
into Focaccia's existing symbolic-expression representation. It does not invoke
LLVM or Miasm's instruction semantics. Miasm is still used for disassembly and
as the expression library; composition, comparison, and trace persistence retain
their existing formats.

Build Rust-helper changes with `nix build .#tir-oracle`. Nix places the helper
in the fetched TIR workspace and resolves its lockfile offline using only the
crate versions vendored from TIR's pinned `Cargo.lock`; the helper's relative
Cargo paths are for that assembled workspace, not a sibling checkout.

The typed specification is prepared once by Nix. The helper derives each
instruction's transformation with runtime registers left symbolic, and the
Python adapter caches it by address and exact instruction bytes. It rejects
other instruction classes, unsupported residual operations or state updates,
and code overlapping the specification profile's known memory. It also checks
that the residual's instruction metadata matches the requested bytes. Memory,
vector, floating-point, branch, and syscall instruction semantics are outside
this first backend's scope. Unsupported instructions never fall back to Miasm;
normal capture fails, while `--force` retains the existing explicit trace-gap
behavior. `FOCACCIA_TIR_ORACLE` can select the helper executable.

The dedicated `checks.<system>.tir-oracle-validation` exercises real
specification-derived arithmetic through evaluation, composition, serialization,
and mismatch detection. `checks.<system>.instruction-semantic-backends` covers
backend selection, protocol failures, and fake-target capture/gap behavior.
These checks need neither RR nor native debugger attachment. They do not claim
that native TIR-backed application capture has been exercised.

`checks.<system>.tir-package-contract` verifies that the Python environment can
use the installed tools and that the AST matches its manifest.
`checks.<system>.tir-packaged-translation` translates and executes a small guest
using the pinned package, without RR or native debugger attachment. Both checks
are available on `aarch64-linux` and `x86_64-linux`.

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

