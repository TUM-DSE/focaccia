# QEMU boundary snapshot plans

The experimental `ta/tir-snapshots` / `ta/plugin-tir-snapshots` protocol can install a reusable register plan while QEMU is stopped in a translation-block execution callback. Plans are identified by TB entry PC and a strictly increasing generation. Each capture is bound to the current TB event sequence and a strictly increasing per-plan occurrence number.

The plugin retains optimizer-safe instrumentation: online mode registers only a TB execution callback. It does not register instruction or memory callbacks and does not decode guest instructions.

## Bounds and failure behavior

- At most 4,096 plans are retained.
- A plan contains 1–32 unique register names of at most 15 bytes each.
- Register values are at most 64 bytes.
- Installation is accepted only at the matching TB boundary.
- Stale generations, unknown registers, duplicate registers, wrong PCs, malformed frames, sequence gaps, and table overflow terminate the controlled execution.
- If a valid register becomes unavailable during capture, the response explicitly requests synchronous fallback. The validator never treats missing evidence as coverage.

The current vertical slice snapshots dependency-derived registers. Plans containing dynamic memory dependencies use the existing synchronous pre-execution reads. Address-recipe evaluation exists and is separately bounded, but dynamic-memory plan framing and source-state byte forwarding remain future work.

## Measured #2248 run

The static-musl AArch64 #2248 workload completed in one QEMU execution per case. The fixed build was accepted and the injected build produced the expected mismatch. Each case covered 351 blocks with 42 plan installations, 126 reused plan occurrences, and 183 explicit synchronous fallbacks. The high fallback count reflects the current dynamic-memory limitation rather than omitted evidence.
