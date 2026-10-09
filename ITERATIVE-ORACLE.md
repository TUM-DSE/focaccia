# Experimental iterative oracle reduction

Branch: `ta/iterative-oracle-reduction` (based on snapshot branch `9feb665`).

The existing TIR specialization cache remains the reusable stage. The new
`focaccia.reduction.ReductionSession` evaluates its symbolic residual for one
entry-state occurrence. It yields `MemoryRequest(address, size)` when a source
memory dependency becomes concrete, accepts exact immutable `bytes` via
`generator.send`, and resumes its saved traversal. Completed DAG nodes are not
recomputed. Generator completion returns the tuple of expected values.

This is resumable evaluation, not per-value recompilation or a new instruction
semantics backend. Only concrete residual operators supported by the existing
expression simplifier are admitted; unresolved operations fail closed.

## Safety and scope

* Register inputs are frozen when the session is constructed.
* The session has no memory-read callback or transport access. Its caller must
  capture requests at the same paused entry boundary, or satisfy them from an
  immutable snapshot. Never service requests with later live memory.
* Each session is single-use and seals on completion/failure. `close()` prohibits
  further evidence delivery or evaluation after boundary release.
* Source bytes are cached by address; overlapping requests fetch only uncached
  ranges. Only the selected conditional arm is evaluated.
* Deferred byte reads use their ordered-write prefix. Forwarded expected writes
  remain a separate overlay and never overwrite original entry bytes or become
  observed output evidence. Prefix cycles and forward references fail closed.
* Node, read-count, source-byte, forwarded-byte, and nested-write-depth limits
  bound resources. Missing register inputs, malformed reads, and unsupported
  operations produce errors, never semantic fallback.

The caller is responsible for binding a session to its boundary; the generic
API cannot prove the origin of bytes supplied by a caller.

## Integration

`tests/probes/tir_no_replay_smoke.py --iterative-reduction` opts into resumable
register-output evaluation and synchronous fallback memory-dependency capture.
Both occur before the existing boundary is released. Plugin snapshot plans,
actual exit-memory comparison, actions, and ordered-store output evaluation
retain their existing paths. The default mode is unchanged.

Reports include `reduction_requests`, `reduction_bytes`, and `reduction_nodes`.
These count evaluator requests (which may be served by the state cache), not
necessarily plugin round trips. No speedup claim is made. Lua still has the
independent exclusive-instruction support gap on this base revision.

## Tests

Run through Nix:

```
nix develop --command python -m pytest -q tests/test_reduction.py \
  tests/test_symbolic_composition.py tests/test_tir_no_replay_smoke.py
```

The TIR oracle and all three trigger fixtures build through Nix. End-to-end
validation passes with iterative reduction enabled using QEMU snapshot revision
`e4e5a436dc9c804718d0d1877182d1ada3cf338a`:

| Trigger | Fixed | Injected | Checked blocks per run |
| --- | --- | --- | --- |
| #2248 | accepted | mismatch | 351 |
| #364 | accepted | mismatch | 360 |
| #2419 | accepted | mismatch | 381 |

All six cases use exactly one QEMU execution and report complete terminal
evidence. The first live attempt exposed an input-capture bug: a slice of X1
required the entire register although only its low 32 bits were available.
Register slices are now frozen independently, with missing inputs rejected only
when their computation is selected. Both cases have dedicated regressions.
The focused suite contains 186 passing tests; Ruff passes.

The root flake's historical QEMU pin does not supply the snapshot protocol.
Use the snapshot source above rather than an unrelated installed plugin. Build
its `with-focaccia-plugin`, `with-focaccia-plugin-2248`,
`with-focaccia-plugin-364`, and `with-focaccia-plugin-2419` Nix packages, then
invoke `tests/probes/tir_no_replay_smoke.py` through `nix develop`, supplying:

```
--iterative-reduction --issue ISSUE --fixture FIXTURE_DIRECTORY
--oracle ORACLE/bin/focaccia-tir-oracle
--qemu-fixed FIXED/bin/qemu-aarch64
--plugin-fixed FIXED/lib/plugins/libfocaccia.so
--qemu-injected INJECTED/bin/qemu-aarch64
--plugin-injected INJECTED/lib/plugins/libfocaccia.so
--tir-revision TIR_REVISION --qemu-revision QEMU_REVISION
--run-directory OUTPUT_DIRECTORY
```

Repeat for all three triggers. Unit tests alone are not sufficient validation
for changes to this path. Results from this run are retained at
`/tmp/carbonara-iterative-e2e-r2-{2248,364,2419}/result.json`.

Regressions cover suspended pointer chasing, completed-node reuse, conditional
reads, overlapping ranges, ordered versions, entry-versus-forwarded bytes,
store-derived pointers, invalid/cyclic dependencies, frozen registers, limits,
read-after-seal rejection, and randomized agreement with the existing evaluator.
