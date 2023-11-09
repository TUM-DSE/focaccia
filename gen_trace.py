import argparse
import lldb
import lldb_target

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

def record_trace(binary: str, args: list[str] = []) -> list[int]:
    # Set up LLDB target
    target = lldb_target.LLDBConcreteTarget(binary, args)

    # Skip to first instruction in `main`
    result = lldb.SBCommandReturnObject()
    break_at_main = f'b -b main -s {target.module.GetFileSpec().GetFilename()}'
    target.interpreter.HandleCommand(break_at_main, result)
    target.run()

    # Run until main function is exited
    trace = []
    while not target.is_exited():
        thread = target.process.GetThreadAtIndex(0)
        func_names = [thread.GetFrameAtIndex(i).GetFunctionName() for i in range(0, thread.GetNumFrames())]
        if 'main' not in func_names:
            break
        trace.append(target.read_register('pc'))
        thread.StepInstruction(False)

    return trace

def main():
    args = parse_args()
    trace = record_trace(args.binary, args.args)
    with open(args.output, 'w') as file:
        for addr in trace:
            print(hex(addr), file=file)
    print(f'Generated a trace of {len(trace)} instructions.')

if __name__ == '__main__':
    main()
