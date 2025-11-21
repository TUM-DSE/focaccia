"""Invocable like this:

    gdb -n --batch -x _qemu_threads.py

But please use `tools/validate_qemu.py` instead because we have some more setup
work to do.
"""

import gdb
import logging
import traceback

from ptrace.debugger import PtraceDebugger
from ptrace.debugger.process_event import NewProcessEvent

from focaccia.snapshot import ReadableProgramState
from focaccia.tools.validate_qemu import make_argparser, verbosity
from focaccia.qemu.target import GDBProgramState, GDBServerConnector
from focaccia.qemu.deterministic import passthrough_system_calls

logger = logging.getLogger('focaccia-qemu-validator')
debug = logger.debug
info = logger.info
warn = logger.warning

class GDBServerStateIterator(GDBServerConnector):
    def __init__(self, remote: str, qemu_pid: int):
        super().__init__(remote)

        self._first_next = True

        self.current_thread_idx = 1
        self.switch_count = 5
        self.threads = [
            self.current_tid()
        ]

        dbg = PtraceDebugger()
        proc = dbg.addProcess(qemu_pid, is_attached=True)
        dbg.addProcess(self.current_tid(), is_attached=True)

    def __iter__(self):
        return self

    def __next__(self) -> ReadableProgramState:
        # The first call to __next__ should yield the first program state,
        # i.e. before stepping the first time
        if self._first_next:
            self._first_next = False
            return GDBProgramState(self._process, gdb.selected_frame(), self.arch)

        state = self._step()
        if state.read_memory(state.read_pc(), 2) == bytes([0x0f, 0x05]):
            # TODO: change thread
            if state.read_register('RAX') in passthrough_system_calls[self.arch.archname]:
                print('Detected clone!')
                state = self._step()
                self.threads.append(state.read_register('RAX'))
            elif len(self.threads) > 1 and self.switch_count <= 0:
                print('Switching threads')
                self.current_thread_idx = ((self.current_thread_idx + 1) % len(self.threads)) + 1
                self.switch_count = 5
                gdb.execute(f'thread {self.current_thread_idx}')
            self.switch_count -= 1

        if self.is_exited():
            raise StopIteration

        return state

def run_multithreaded_deterministic(gdb: GDBServerStateIterator):
    state_iter = iter(gdb)
    cur_state = next(state_iter)

    # An online trace matching algorithm.
    while True:
        try:
            cur_state = next(state_iter)
            tid = state_iter.current_tid()
            info(f'[{tid}] Validating instruction at address {hex(cur_state.read_pc())}')
        except StopIteration:
            break
        except Exception as e:
            print(traceback.format_exc())
            raise e

def main():
    args = make_argparser().parse_args()

    logging_level = getattr(logging, args.error_level.upper(), logging.INFO)
    logging.basicConfig(level=logging_level, force=True)

    try:
        gdb_server = GDBServerStateIterator(args.remote, args.qemu_pid)
    except Exception as e:
        raise Exception(f'Unable to perform basic GDB setup: {e}')

    # Use symbolic trace to collect concrete trace from QEMU
    try:
        run_multithreaded_deterministic(gdb_server)
    except Exception as e:
        raise Exception(f'Failed to collect concolic trace from QEMU: {e}')

if __name__ == "__main__":
    main()

