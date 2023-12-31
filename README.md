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

`focaccia.py` is the main executable. Invoke `focaccia.py --help` to see what you can do with it.

## Tools

The `tools/` directory contains additional utility scripts to work with focaccia.

 - `convert.py`: Convert logs from QEMU or Arancini to focaccia's snapshot log format.

## Project Overview (for developers)

### Snapshot-comparison framework

The following files belong to a rough framework for the snapshot comparison engine:

 - `focaccia/snapshot.py`: Structures used to work with snapshots. The `ProgramState` class is our primary
representation of program snapshots.

 - `focaccia/compare.py`: The central algorithms that work on snapshots.

 - `focaccia/arch/`: Abstractions over different processor architectures. Will be used to integrate support for more
architectures later. Currently, we only have X86.

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

 - `miasm_test.py`: A test script that traces a program concolically.
