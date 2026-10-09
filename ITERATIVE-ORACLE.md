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

The TIR oracle and all three trigger fixtures build through Nix. Live trigger
validation was attempted but the surviving QEMU plugin artifact rejects this
branch's launch identity options before execution. Historical fixed/injected
QEMU store paths are unavailable. These attempts are not successful end-to-end
checks; a matching snapshot-branch QEMU build is still needed.

Regressions cover suspended pointer chasing, completed-node reuse, conditional
reads, overlapping ranges, ordered versions, entry-versus-forwarded bytes,
store-derived pointers, invalid/cyclic dependencies, frozen registers, limits,
read-after-seal rejection, and randomized agreement with the existing evaluator.
