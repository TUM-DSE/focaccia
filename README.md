# Focaccia

This repository contains initial code for comprehensive testing of binary
translators.

## Requirements

For Python dependencies, see the `requirements.txt`. We also require at least LLDB version 17 for `fs_base`/`gs_base`
register support.

I had to compile LLDB myself; these are the steps I had to take (you also need swig version >= 4):

```
git clone https://github.com/llvm/llvm-project <llvm-path>
cd <llvm-path>
cmake -S llvm -B build -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS="clang;lldb" -DLLDB_ENABLE_PYTHON=TRUE -DLLDB_ENABLE_SWIG=TRUE
cmake --build build/ --parallel $(nproc)

# Add the built LLDB python bindings to your PYTHONPATH:
PYTHONPATH="$PYTHONPATH:$(./build/bin/lldb -P)"
```

It will take a while to compile.

## How To Use

`focaccia` is the main executable. Invoke `focaccia --help` to see what you can do with it.

### QEMU

A number of additional tools are included to simplify use when validating QEMU:
`capture-transforms`, `convert-log`, `validate-qemu`, `validation_server`. They enable the following workflow.

```bash
capture-transforms -o oracle.trace bug.out
qemu-x86_64 -g 12345 bug.out &
validate-qemu --symb-trace oracle.trace localhost 12345
```

Alternatively if you have access to the focaccia QEMU plugin:

```bash
validation_server.py --symb-trace oracle.trace --use-socket=/tmp/focaccia.sock --guest_arch=<arch>
```
After you see `Listening for QEMU Plugin connection at /tmp/focaccia.sock...` you can start QEMU like this:
```bash
qemu-<arch> [-one-insn-per-tb] --plugin build/contrib/plugins/libfocaccia.so <bug.out>
```

Using this workflow, Focaccia can determine whether a mistranslation occured in that particular QEMU run.

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

 - `focaccia/snapshot.py`: Structures used to work with snapshots. The `ProgramState` class is our primary
representation of program snapshots.

 - `focaccia/compare.py`: The central algorithms that work on snapshots.

 - `focaccia/arch/`: Abstractions over different processor architectures. Currently we have x86 and aarch64.

### Concolic execution

The following files belong to a prototype of a data-dependency generator based on symbolic
execution:

 - `focaccia/symbolic.py`: Algorithms and data structures to compute and manipulate symbolic program transformations.
This handles the symbolic part of "concolic" execution.

 - `focaccia/lldb_target.py`: Tools for executing a program concretely and tracking its execution using
[LLDB](https://lldb.llvm.org/). This handles the concrete part of "concolic" execution.

 - `focaccia/miasm_util.py`: Tools to evaluate Miasm's symbolic expressions based on a concrete state. Ties the symbolic
and concrete parts together into "concolic" execution.

### Helpers

 - `focaccia/parser.py`: Utilities for parsing logs from Arancini and QEMU, as well as serializing/deserializing to/from
our own log format.

 - `focaccia/match.py`: Algorithms for trace matching.

### Supporting new architectures

To add support for an architecture <arch>, do the following:

 - Add a file `focaccia/arch/<arch>.py`. This module declares the architecture's description, such as register names and
an architecture class. The convention is to declare state flags (e.g. flags in RFLAGS for x86) as separate registers.

 - Add the class to the `supported_architectures` dict in `focaccia/arch/__init__.py`.

 - Depending on Miasm's support for <arch>, add register name aliases to the `MiasmSymbolResolver.miasm_flag_aliases`
dict in `focaccia/miasm_util.py`.

 - Depending on the existence of a flags register in <arch>, implement conversion from the flags register's value to
values of single logical flags (e.g. implement the operation `RFLAGS['OF']`) in the respective concrete targets (LLDB,
GDB, ...).
