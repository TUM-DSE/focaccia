# Deterministic replay fixtures

`x86_64-signal-uapi.json` records the Linux x86-64 UAPI offsets consumed by
Focaccia's signal-frame validator. The fixed context offsets come from Linux
`include/uapi/asm/sigcontext.h` and `asm-generic/ucontext.h`; the outer
`pretcode`/handler-register relationship is cross-checked against the pinned
QEMU `linux-user/i386/signal.c`. Signal-info and variable FP/XSTATE addresses
are deliberately read from RR's recorded handler registers and frame bytes,
not inferred from an ad-hoc total frame size.
