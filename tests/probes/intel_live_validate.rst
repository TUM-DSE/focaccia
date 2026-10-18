Online Intel/TIR probe
======================

``intel_live_validate.py`` is a fail-closed integration driver, not a second x86
implementation. It runs the selected software-SHA BusyBox under optimized QEMU
TB callbacks and decodes instruction bytes from the paused pre-boundary using
exact XED forms; a development disassembly inventory is never runtime input.

The default path imports source residuals into Focaccia's source-owned
``SymbolicTransform`` pipeline, composes them with
``SymbolicTransformComposer``, and predicts/compares through
``boundary_oracle``. Reports identify it as ``intel-symbolic-source``. The
legacy concrete evaluator is available only with ``--concrete-diagnostic``
and is labeled ``intel-concrete-evaluator-legacy``; it is diagnostic only.

.. code-block:: sh

    # Use the checked submodule, not an older default flake input pin.
    nix build path:./qemu#with-focaccia-plugin -o /tmp/carbonara-qemu
    nix build path:../tir#intel-eval -o /tmp/carbonara-intel-eval
    nix develop --command python tests/probes/intel_live_validate.py \
      --qemu /tmp/carbonara-qemu/bin/qemu-x86_64 \
      --plugin /tmp/carbonara-qemu/lib/plugins/libfocaccia.so \
      --oracle /tmp/carbonara-intel-eval/bin/intel-eval \
      --model /tmp/carbonara-usermode-full/typed.json \
      --guest-base 0x800000000000 --guest-limit 0x800000000000 \
      --output /tmp/intel-symbolic-live-report.json
    nix develop --command python tests/probes/test_intel_live_validate.py
    # Opt into actual source-evaluator fixture tests (private model required):
    INTEL_LIVE_MODEL=/tmp/carbonara-usermode-full/typed.json \
      INTEL_LIVE_ORACLE=/tmp/carbonara-intel-eval/bin/intel-eval \
      nix develop --command pytest -q tests/probes/test_intel_live_validate.py


The report's ``semantic_validation`` and ``whole_program_completed`` remain false
until every boundary, exit syscall, independent stdout digest, exit status, and
in-run deliberately corrupted observed-state negative control pass. Failure is
not a validation success. The JSONL evidence artifact records actual input
registers separately from predictions, decoded bytes, and lazy input memory.

Symbolic convergence mode
-------------------------

The importer binds each residual to the exact PC, opcode bytes, XED iform,
selected profile, and frozen model hash. Conditional effects retain ordered
write-prefix slots (including inactive writes); pre-boundary reads are
permission checked and fetched lazily. It never falls back to concrete
instruction evaluation.

Accepted native AArch64-host BusyBox software-SHA run:
``/tmp/intel-symbolic-live-report-20261019-finaloracle.json`` and its
``.evidence.jsonl`` companion. It completed 3,064 TB transitions, 16,998
architectural instructions, and 17,024 source steps. All 3,115 event intervals
had passive store-footprint coverage, and 10,344 predicted byte writes matched
independent post-memory evidence. Stdout matched
``713784ad24639a95b1c764f5cced9985c72fff472df3c4650e8ac8f05f4cc922`` and
exit_group returned status zero. All 26 syscall cutpoints and in-run wrong-PC,
syscall RBX/XMM preservation, resumed-PC, and unexpected-store controls passed.
Earlier failed symbolic runs remain under distinct timestamped paths and are
not acceptance evidence.

Controlled address layout
-------------------------

On the tested AArch64 host, unconstrained QEMU x86-64 linux-user placed the
initial stack at ``0x0000fffff67bedc0``, which is not canonical with LA57 disabled.
The source correctly predicted #SS on CALL; validation stopped *before* guest
advance. This is retained in ``/tmp/intel-live-noncanonical-negative.json``;
it is not a claim that QEMU delivered a fault. QEMU rejects bounded ``-R`` for
x86-64 because of its fixed high-negative vsyscall page. The approved launch
instead uses ``-B 0x800000000000`` and asserts every observed PC/RSP, accessed
memory interval, and passive guest-store span lies below ``2**47``. This changes
actual placement at launch, never register observations or source canonicality.
The legacy vsyscall mapping is outside this ordinary user range and accessing
it is unsupported. Both placement and limit are included in launch identity.

Trust boundary
--------------

* Each model boundary executes source ``User_Reset``, then overlays captured GPR,
  RFLAGS, XMM and FS/GS bases. Upper inaccessible vector lanes must not become
  known merely because reset supplied zero. QEMU's 32-bit EFLAGS observation is
  zero-extended only across architecturally reserved RFLAGS bits 63:32. Register
  evidence widths are checked before overlay. The selected ``qemu64`` profile has
  SHA, AVX and CET execution features disabled; decoder classification does not
  enable processor features.
* Missing model memory is requested while QEMU is still at the pre-boundary;
  transactional evaluator failure must preserve the pre-instruction state.
  Memory permissions require an independent guest-page observer. Host ``/proc``
  mappings and successful reads do **not** establish guest write permission.
  Missing permissions or unsupported evaluator diagnostics abort the run.
* At the successor boundary the driver compares model PC/GPR/defined flag bits,
  observable vector bits, and every dirty byte to independent actual evidence.
  Unknown GPR or observable XMM predictions fail closed; only unspecified flag
  bits and inaccessible upper vector lanes are exempt from value comparison.
  No post-memory is provided as the preceding instruction's model input.
  Instruction extents also require independently observed guest execute
  permission. Predicted-address comparisons alone cannot detect extra actual
  stores: full success requires exact source-dirty/actual-store address coverage
  at every boundary, with event identities and overflow checked by transport.
  A deliberately added observed store must also be rejected after a positive
  baseline comparison.
* SYSCALL is a named environment cutpoint. Source-saved syscall prestate is
  compared at entry. Linux x86-64 ordinary-return ABI preservation is checked
  both at the return callback and the successor TB: every GPR except RAX/RCX/R11,
  XMM0..15, EFLAGS, and FS/GS bases must equal independently captured preaction
  values. Only ARCH_SET_FS/ARCH_SET_GS explicitly permit their respective base
  output. Return-event PC evidence is unavailable and is never represented as
  an architectural zero: the source Next_IP obligation remains pending until
  the first resumed TB, where exact PC equality is mandatory before rebasing.
  Unexpected EOF/other actions cannot discharge it. A corrupted resumed-PC
  negative control must fail. RAX/RCX/R11 and OS-written memory
  are environment outputs, not claimed CPU predictions; no rebase discards the
  other obligations. Nonlocal returns/process creation fail closed. Deliberate
  RBX and XMM corruption across a syscall must be rejected. The exit syscall
  entry must be checked before terminal EOF is accepted.
* The embedding's flat user-mode, no-debug/no-asynchronous-event contract and
  stride-one source REP policy apply. Optimized QEMU completes REP internally;
  the driver composes the original Step_REP repeatedly while the source's
  repeat flag and RIP request another stride, until source completion, all
  while QEMU remains paused. It never obtains iteration counts from poststate.
  Available Intel kernels are not manually
  replaced by this driver. Missing-definition/environment bindings and retained
  original bodies are identified by the private model manifest; see
  ``../tir/docs/intel-usermode-model.md`` for that separate provenance contract.

Validated execution
-------------------

The historical completed report in ``/tmp/intel-live-report.json`` is a
legacy concrete-evaluator baseline and is not symbolic acceptance evidence.
The accepted symbolic report and counts are recorded above. The prior concrete
audit remains at ``/tmp/intel-live-final-audit.json``.

Do not infer whole-program coverage from unit/synthetic tests or successful
model typechecking. Only an actual report with both completion/validation flags
true demonstrates a completed run. Prediction counts are recorded separately
from independently checked instruction counts; SYSCALL cutpoints are reported
separately rather than counted as checked CPU output transitions.
