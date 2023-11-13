# DBT Testing

This repository contains initial code for comprehensive testing of binary
translators.

## Snapshot-comparison framework

The following files belong to a rough framework for the snapshot comparison engine:

 - `main.py`: Entry point to the tool. Handling of command line arguments, pre-processing of input
logs, etc.

 - `snapshot.py`: Internal structures used to work with snapshots. Contains the previous
`ContextBlock` class, which has been renamed to `ProgramState` to make its purpose as a snapshot of
the program state clearer.

 - `compare.py`: The central algorithms that work on snapshots.

 - `run.py`: Tools to execute native programs and capture their state via an external debugger.

 - `arancini.py`: Functionality specific to working with arancini. Parsing of arancini's logs into our
snapshot structures.

 - `arch/`: Abstractions over different processor architectures. Will be used to integrate support for
more architectures later. Currently, we only have X86.

## Symbolic execution

The following files belong to a prototype of a data-dependency generator based on symbolic
execution:

 - `symbolic.py`: Algorithms and data structures to compute and manipulate symbolic program
transformations.

 - `gen_trace.py`: An invokable tool that generates an instruction trace for an executable's native
execution. Is imported into `trace_symbols.py`, which uses the core function that records a trace.

 - `trace_symbols.py`: A simple proof of concept for symbolic data-dependency tracking. Takes an
executable as an argument and does the following:

    1. Executes the program natively (starting at `main`) and records a trace of every instruction
executed, stopping when exiting `main`.

    2. Tries to follow this trace of instructions concolically (keeps a concrete program state from
a native execution in parallel to a symbolic program state), recording after each instruction the
changes it has made to the program state before that instruction.

    3. Writes the program state at each instruction to log files; writes the concrete state of the
real execution to 'concrete.log' and the symbolic difference to 'symbolic.log'.

 - `interpreter.py`: Contains an algorithm that evaluates a symbolic expression to a concrete value,
using a reference state as input.

## Helpers

 - `lldb_target.py`: Implements angr's `ConcreteTarget` interface for [LLDB](https://lldb.llvm.org/).
