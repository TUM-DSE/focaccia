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

## Snapshot-comparison framework

The following files belong to a rough framework for the snapshot comparison engine:

 - `main.py`: Entry point to the tool. Handling of command line arguments, pre-processing of input logs, etc.

 - `snapshot.py`: Structures used to work with snapshots. The `ProgramState` class is our primary representation of
program snapshots.

 - `compare.py`: The central algorithms that work on snapshots.

 - `arancini.py`: Functionality specific to working with arancini. Parsing of arancini's logs into our snapshot
structures.

 - `arch/`: Abstractions over different processor architectures. Will be used to integrate support for more
architectures later. Currently, we only have X86.

## Concolic execution

The following files belong to a prototype of a data-dependency generator based on symbolic
execution:

 - `symbolic.py`: Algorithms and data structures to compute and manipulate symbolic program transformations. This
handles the symbolic part of "concolic" execution.

 - `lldb_target.py`: Tools for executing a program concretely and tracking its execution using
[LLDB](https://lldb.llvm.org/). This handles the concrete part of "concolic" execution.

 - `miasm_util.py`: Tools to evaluate Miasm's symbolic expressions based on a concrete state. Ties the symbolic and
concrete parts together into "concolic" execution.

## Helpers

 - `miasm_test.py`: A test script that traces a program concolically.
