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

Plans snapshot dependency-derived registers and dynamic memory whose source-state addresses compile to the bounded target-neutral recipe language. Recipes support ordered pointer chasing and arithmetic; final reads preserve exact addresses and bytes, including overlapping aliases. Dependencies using unsupported expressions, non-current address states, invalid reads, or resource overflow explicitly use synchronous pre-execution fallback. Intra-block store forwarding is not inferred: plans requiring it remain synchronous.

Capture commands still synchronize at every TB boundary. This is coherent and reusable but is not asynchronous validation; a future evidence queue must add bounded backpressure and action/completion barriers before synchronization can be reduced.

## Measured #2248 run

All static-musl AArch64 regression workloads completed in one QEMU execution per fixed/injected case. Fixed builds were accepted and injected builds produced their expected mismatch.

| issue | blocks | installs | reused occurrences | explicit fallbacks |
|---|---:|---:|---:|---:|
| #2248 | 351 | 50 | 126 | 175 |
| #364 | 360 | 54 | 125 | 181 |
| #2419 | 381 | 55 | 138 | 188 |

For #364, validation rereads and compares actual final guest memory after the block; expected write descriptions alone are not treated as evidence.
