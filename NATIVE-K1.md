# Experimental staged reduction and native oracle tier

Branches: Focaccia `ta/iterative-oracle-jit`, TIR `ta/carbonara-oracle-jit`.
Enable with `tests/probes/tir_no_replay_smoke.py --native-jit`.
This implies `--iterative-reduction`; the default remains unchanged.

## Actual pipeline

1. The existing TIR oracle specializes the ISA specification for exact instruction
   bytes, PC, and configuration. Focaccia composes its exported transformations.
2. Pure scalar regions of those specification-derived transformations are
   mechanically re-expressed as typed TIR kernels. Memory accesses, selected
   register slices, and other operations become scalar input slots. They are
   evaluated by the resumable evaluator, not by generated guest-memory code.
3. TIR reduces each kernel with its literal inputs known and retains this
   parameterized TIR residual. On hot occurrences, up to three one-bit input
   slots are bound to their current values. TIR reduces the retained residual
   again. This is input-binder specialization, **not** architecture configuration
   pinning. Wider changing operands remain parameters.
4. A bounded LLVM backend compiles the reduced kernel. A persistent process
   retains its execution engine. Variant selection includes all bound input
   values, so reuse checks the specialization guards rather than trusting that
   flags stayed constant. Fresh unbound operands are passed on every invocation.
5. Native results feed the existing architectural comparison. Observed exit
   values never become specialization bindings for their own expected results.

The new native tier is deliberately pure. It does not JIT the complete guest
machine interpreter or issue OS actions. This avoids treating runtime memory as
immutable configuration and avoids passing guest pointers to generated code.
It is a full staged-reduction/guarded-cache/native-execution path for the admitted
scalar regions, not a claim that every residual primitive now has native support.

## Coverage and resource policy

The importer admits bitvector addition, subtraction, multiplication, AND, OR,
XOR, and concatenation at widths 1--128. The LLVM backend additionally handles
pure forms produced by reduction, including static bit slices and complement.
Condition selection, memory, ordered-store forwarding, and other supported
residual operations retain the existing evaluator. This is a performance tier
of the same specification-derived oracle, not a replacement instruction model.
A selected native kernel's compilation or execution failure fails validation;
it is not silently retried through another oracle.

A region becomes hot on its second encounter. Code context and normalized
kernel shape identify the template; runtime one-bit bindings identify variants.
The policy permits at most eight binding combinations per template. The process
retains 128 TIR templates and 256 native variants with FIFO eviction, and stops
at 10,000 compilations. The Python planning and frequency tables retain at most
512 and 2,048 entries. Wire size, tree depth, node count, parameter count, and
response time are bounded. These are initial policy choices, not optimality
claims.

## Evidence-only native ABI

The generated function accepts scalar input slots and a two-word output buffer.
All loads address statically assigned slots whose count and widths are checked
before invocation. All stores target the two allocated output words. The emitted
LLVM IR has no memory callback, system call, external call, or conversion of a
scalar guest address into a host pointer. LLVM integer operations preserve
bitvector truncation; concatenation and slice shifts are bounded by their types.

The existing reduction session freezes register inputs, yields exact source
memory requests at the paused boundary, and keeps entry bytes separate from
expected ordered writes. Native kernels consume those captured or derived
values. Actual output-store evidence is still collected and compared separately.

## Validation and measurement

`FOCACCIA_NATIVE_ORACLE=/path/to/focaccia-tir-oracle` enables the real native
integration tests in `tests/test_native_oracle.py`. They check randomized
arithmetic at six widths through 128 bits, changing runtime carry bindings,
variant reuse, cache eviction, and multioperation evaluation after pointer
chasing. The carry test specializes a one-bit carry inside a wider addition,
changes it between occurrences, and requires two compiled variants and reuse.

Nix check `tir-native-kernels` executes these tests with the packaged oracle.
Nix check `tir-native-jit-e2e` executes all three fixed/injected controls and
requires nonzero native calls, compilations, and variant hits in every case.
The latter needs the snapshot QEMU source at
`e4e5a436dc9c804718d0d1877182d1ada3cf338a`, supplied through an input override:

```
system=$(nix eval --impure --raw --expr builtins.currentSystem)
nix build ".#checks.$system.tir-native-jit-e2e" \
  --override-input qemu-submodule 'git+file:///PATH/TO/QEMU?ref=ta/plugin-tir-snapshots&shallow=1' \
  --no-write-lock-file
```

Reports separate native calls, template and variant hits, compilations,
guarded calls, TIR reduction time, LLVM compilation time, and native-service
round-trip time. Round-trip time includes compilation on misses and must not
be added to compile time as an independent cost. End-to-end timing also includes
original ISA specialization, observation, and comparison. A functioning JIT is
not evidence of a speedup; compilation and IPC overhead must be measured against
the non-native mode with identical observation scope.

### Initial end-to-end results

On the AArch64 development host, all three fixed/injected pairs passed in both
native and interpreted modes. Each case used one QEMU execution and complete
terminal evidence. The fixed runs were accepted; the injected runs reported
mismatches. The native path was actually exercised in every case:

| Trigger | Native calls per fixed run | Compilations | Variant hits | Guarded calls |
| --- | ---: | ---: | ---: | ---: |
| #2248 | 3484 | 461 | 3023 | 271 |
| #364 | 3643 | 531 | 3112 | 269 |
| #2419 | 5551 | 643 | 4908 | 313 |

Exploratory wall times for each fixed/injected pair were 81.59/75.44 seconds
(native/interpreted) for #2248, 93.22/85.30 for #364, and 96.72/91.01 for #2419.
These single samples are not a controlled performance study; other development
jobs ran on the host. They show no end-to-end speedup. Native compilation alone
cost 1.4--1.9 seconds per case. Compilation amortization, tiering policy, region
size, and IPC remain performance work rather than established benefits.

Artifacts: `/tmp/carbonara-native-k1-r2-{jit,interpreted}-{2248,364,2419}/`;
combined timing and result records: `/tmp/carbonara-native-k1-comparison.json`.
