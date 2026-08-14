# Native x86-64 RR/QEMU smoke fixture

`x86_64-file-read.S` is a static, non-PIE, single-thread Linux x86-64 program
with no libc or dynamic-loader dependency. It opens the path in `argv[1]`,
reads at most 64 bytes, writes the bytes to standard output, closes the file,
and exits. `_focaccia_trace_start` and `_focaccia_trace_stop` delimit the
syscall-only validation region.

The flake builds this source only on native `x86_64-linux`. The fixture is an
initial integration scenario, not evidence for signal replay, concurrency,
AArch64 replay, or the paper corpus.
