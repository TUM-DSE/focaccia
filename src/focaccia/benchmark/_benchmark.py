from focaccia.tools.benchmark_focaccia import make_argparser
from focaccia.benchmark.timer import Timer
from focaccia.qemu import _qemu_tool
from focaccia.deterministic import DeterministicLog
from focaccia.compare import compare_symbolic
import focaccia.parser as parser

import gdb
import subprocess
import time

def main():
    print("Benchmarking focaccia")
    args = make_argparser().parse_args()

    detlog = DeterministicLog(args.deterministic_log)
    if args.deterministic_log and detlog.base_directory is None:
        raise NotImplementedError(f'Deterministic log {args.deterministic_log} specified but '
                                   'Focaccia built without deterministic log support')

    # Emu exec continue
    try:
        timer = Timer("Emulator execution (continue)", paused=True, iterations=args.iterations)
        for i in range(timer.iterations):
            qemu_process = subprocess.Popen(
                [f"qemu-{args.guest_arch}", "-g", args.port, args.binary],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(0.5)
            timer.unpause()
            gdb_server = _qemu_tool.GDBServerStateIterator(f"localhost:{args.port}", detlog)
            gdb.execute("continue")
            qemu_process.wait()
            timer.pause()
        timer.log_time()
    except Exception as e:
        raise Exception(f'Unable to benchmark QEMU: {e}')

    # Emu exec stepping
    try:
        timer = Timer("Emulator execution (stepping)", paused=True, iterations=args.iterations)
        for i in range(timer.iterations):
            try:
                qemu_process = subprocess.Popen(
                        [f"qemu-{args.guest_arch}", "-g", args.port, args.binary],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(0.5)
                timer.unpause()
                gdb_server = _qemu_tool.GDBServerStateIterator(f"localhost:{args.port}", detlog)
                state_iter = iter(gdb_server)
                while True:
                    cur_state = next(state_iter)
            except StopIteration:
                timer.pause()
        timer.log_time()
    except Exception as e:
        raise Exception(f'Unable to benchmark QEMU: {e}')

    try:
        with open(f"/tmp/benchmark-{args.binary.split('/')[-1]}-symbolic.trace", 'r') as strace:
            symb_transforms = parser.parse_transformations(strace)
    except Exception as e:
        raise Exception(f'Failed to parse state transformations from native trace: {e}')

    # emu exec tracing
    try:
        timer = Timer("Emulator tracing", iterations=args.iterations, paused=True)
        for i in range(timer.iterations):
            if timer.enabled:
                qemu_process = subprocess.Popen(
                        [f"qemu-{args.guest_arch}", "-g", args.port, args.binary],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(0.5)
                timer.unpause()
                gdb_server = _qemu_tool.GDBServerStateIterator(f"localhost:{args.port}", detlog)

            conc_states, matched_transforms = _qemu_tool.collect_conc_trace(
                gdb_server,
                symb_transforms.states,
                symb_transforms.env.start_address,
                symb_transforms.env.stop_address)
            timer.pause()
        timer.log_time()
    except Exception as e:
        raise Exception(f'Failed to collect concolic trace from QEMU: {e}')

    # emu exec testing
    try:
        timer = Timer("Emulator testing", iterations=args.iterations)
        for i in range(timer.iterations):
            res = compare_symbolic(conc_states, matched_transforms)
        timer.log_time()
    except Exception as e:
        raise Exception('Error occured when comparing with symbolic equations: {e}')

if __name__ == "__main__":
    main()
