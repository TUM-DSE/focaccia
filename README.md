# Focaccia

This repository contains the source code for Focaccia, a comprehensive validator for CPU emulators
and binary translators.

## Requirements

Python dependencies are handled via pyproject and uv. We provide first-class support for Nix via our
flake, which integrates with our Python uv environment via uv2nix. 

We do not support any other build system officially but Focaccia has been known to work on various
other systems also, as long as its Python dependencies are provided.

## How To Use

`focaccia` is the main executable. Invoke `focaccia --help` to see what you can do with it.

### QEMU

A number of additional tools are included to simplify use when validating QEMU:
`capture-transforms`, `convert-log`, `validate-qemu`, `validation_server`. They enable the following workflow.

```bash
capture-transforms -o oracle.trace bug.out
qemu-x86_64 -g 12345 bug.out &
validate-qemu --symb-trace oracle.trace --remote localhost:12345
```

The above workflow works for reproducing most QEMU bugs but cannot handle the following two cases:

1. Optimization bugs

2. Bugs in non-deterministic programs

We provide alternative approaches for dealing with optimization bugs. Focaccia currently does not
handle bugs in non-deterministic programs.

### QEMU Optimization bugs 

When a bug is suspected to be an optimization bug, you can use the Focaccia QEMU plugin. The QEMU
plugin is exposed, along with the QEMU version corresponding to it, under the qemu-plugin package in
the Nix flake.

It is used as follows:

```bash
validate-qemu --symb-trace oracle.trace --use-socket=/tmp/focaccia.sock --guest_arch=arch
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
rr record -o bug.rr.out
rr replay -s 12345 bug.rr.out
capture-transforms --remote localhost:12345 --deterministic-log bug.rr.out -o oracle.trace bug.out
```

Note: the `rr replay` call prints the correct binary name to use when invoking `capture-transforms`,
it also prints program output. As such, it should be invoked separately as a foreground process.

Note: we currently do not support validating such programs on QEMU.

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

