import argparse
import lldb
import lldb_target

def record_trace(binary: str,
                 args: list[str] = [],
                 func_name: str | None = 'main') -> list[int]:
    """
    :param binary:    The binary file to execute.
    :param args:      Arguments to the program. Should *not* include the
                      executable's location as the usual first argument.
    :param func_name: Only record trace of a specific function.
    """
    # Set up LLDB target
    target = lldb_target.LLDBConcreteTarget(binary, args)

    # Skip to first instruction in `main`
    if func_name is not None:
        result = lldb.SBCommandReturnObject()
        break_at_func = f'b -b {func_name} -s {target.module.GetFileSpec().GetFilename()}'
        target.interpreter.HandleCommand(break_at_func, result)
        target.run()

    # Run until main function is exited
    trace = []
    while not target.is_exited():
        thread = target.process.GetThreadAtIndex(0)

        # Break if the traced function is exited
        if func_name is not None:
            func_names = [thread.GetFrameAtIndex(i).GetFunctionName() \
                          for i in range(0, thread.GetNumFrames())]
            if func_name not in func_names:
                break
        trace.append(target.read_register('pc'))
        thread.StepInstruction(False)

    return trace

def parse_args():
    prog = argparse.ArgumentParser()
    prog.add_argument('binary',
                      help='The executable to trace.')
    prog.add_argument('-o', '--output',
                      default='breakpoints',
                      type=str,
                      help='File to which the recorded trace is written.')
    prog.add_argument('--args',
                      default=[],
                      nargs='+',
                      help='Arguments to the executable.')
    return prog.parse_args()

def main():
    args = parse_args()
    trace = record_trace(args.binary, args.args)
    with open(args.output, 'w') as file:
        for addr in trace:
            print(hex(addr), file=file)
    print(f'Generated a trace of {len(trace)} instructions.')

if __name__ == '__main__':
    main()
