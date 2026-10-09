# Reduce the specification before specializing each instruction

The scalar native tier is not the dominant optimization. Profiling 442 distinct
instructions from the existing #2248 validation artifact showed approximately
30 seconds in decode/pruning and 45 seconds in configuration folding, out of
95 seconds total. Instruction specialization took 9 seconds and residual export
0.03 seconds. This development probe runs the oracle only; it is not a discovery
execution used by validation.

## Implemented stages

1. **Specification and configuration lifetime.** Each persistent oracle worker
   owns one immutable prepared module and one configuration cache. Its source
   identity cannot change during that lifetime.
2. **Configured semantic class.** The specification decoder determines the
   instruction class. On a miss, TIR prunes to that class and folds the declared
   configuration. The resulting real TIR module keeps instruction bits, PC, and
   remaining runtime state symbolic. Subsequent encodings in that class reuse
   this module instead of repeating pruning and configuration folding.
3. **Exact instruction.** The retained class module is specialized for the exact
   instruction bytes and PC using a fresh output module. Position-dependent
   results are never reused merely because instruction bytes match. The existing
   Python transformation cache retains its exact `(PC, bytes)` identity.
4. **Execution inputs.** The existing resumable evaluator obtains entry evidence.
   The optional scalar native tier can additionally reduce and compile pure
   regions, as described in `NATIVE-K1.md`. It remains opt-in because it is slower
   than the class-cached interpreted mode on the current short workloads.

This is reuse of specification-level reduction, not just faster evaluation of
already-exported symbolic expressions. It does not introduce runtime architectural
invariants or substitute observed results for expected values.

## Safety and bounds

All instruction admission checks run before accessing the configured module,
including the exact-opcode restrictions on partially audited classes. A cached
MUL class therefore does not admit an unaudited MUL encoding. Address alignment,
address-space overflow, and overlap with configuration memory are still checked
on every request.

The class cache defaults to 16 LRU entries and a 32 MiB serialized-declaration
budget per worker. This is a representation-size budget, not a heap-RSS claim.
An oversized module is used without being retained. A separate FIFO memo holds
at most 1,024 opcode-to-class classifications; it caches no transitions or
PC-dependent values. `FOCACCIA_ORACLE_CLASS_CACHE=0` retains the original uncached
pipeline for comparison. Capacities outside 0--64 are rejected.

## Validation

The 442-request corpus produced identical complete response hashes with and
without reuse. Integration tests compare capacities 0, 1, and 16, covering
position-dependent ADR results, differing ADD immediates and destination
registers, 32-bit versus 64-bit encodings, eviction, and rejection of an unaudited
sibling after an admitted instruction.

All three fixed/injected controls pass end-to-end in three modes: uncached,
class-cached, and class-cached plus native kernels. These are 18 independent
single-QEMU runs, each with complete terminal evidence. Fixed runs are accepted
and injected regressions produce architectural mismatches. Validation scope and
instruction specialization counts are held constant.

| Fixed/injected pair | Uncached | Class cache | Class cache + scalar JIT |
| --- | ---: | ---: | ---: |
| #2248 | 75.13 s | 33.66 s | 37.12 s |
| #364 | 84.09 s | 37.92 s | 41.98 s |
| #2419 | 90.59 s | 40.13 s | 45.08 s |

These are exploratory single samples, not confidence intervals. Class reuse
improved measured end-to-end time by approximately 2.2x. The serial oracle-only
corpus improved from 95.09 to 26.73 seconds (3.56x), with 400 class hits and
42 misses. In the live four-worker #2248 run, 442 requests required 77 configured
class builds rather than 442. Worker timings are overlapping wall times and
must not be summed and reported as end-to-end latency.

Artifacts:

* `/tmp/carbonara-oracle-stages-{baseline,cached}.json`
* `/tmp/carbonara-class-e2e-comparison.json`
* `/tmp/carbonara-class-e2e-{baseline,classes,classes-jit}-{2248,364,2419}/`

## Reproduction

Use the matched QEMU snapshot builds documented in `ITERATIVE-ORACLE.md` and
`NATIVE-K1.md`. The live harness accepts `--oracle-class-cache 0` or
`--oracle-class-cache 16`, plus `--oracle-profile` to record per-worker stages
in the final report. Add `--native-jit` only for the native-tier ablation.

`tests/probes/profile_tir_stages.py` profiles oracle requests using code from an
existing validation report and its immutable ELF. It records response hashes so
changes can be compared independently of timings. Profiles are emitted once per
worker on stderr at EOF, avoiding per-request diagnostic pipe backpressure.
