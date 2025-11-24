import os
import signal
import socket
import subprocess
import select

import ptrace.debugger
from ptrace.debugger import (
    ProcessExit,
    ProcessEvent,
    ProcessSignal,
    NewProcessEvent,
    ProcessExecution,
)

# If scheduler does not provide input within this time (seconds),
# continue running the last chosen thread.
SCHED_TIMEOUT = 0

class Scheduler:
    def __init__(self, sched_socket_path: str = '/tmp/memcached_scheduler.sock'):
        self.debugger = ptrace.debugger.PtraceDebugger()
        self.debugger.traceClone()
        self.debugger.traceFork()
        self.debugger.traceExec()

        self._first_clone_ignored = False
        self._ignored_tid = None

        if os.path.exists(sched_socket_path):
            os.unlink(sched_socket_path)

        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(sched_socket_path)
        self.srv.listen(1)

        print(f"Waiting for scheduler connection on {sched_socket_path}")
        self.conn, _ = self.srv.accept()
        print("Scheduler connected")


    def _next(self, processes, current_proc):
        """
        processes: dict[tid] -> PtraceProcess
        current_proc: PtraceProcess or None
        """
        timeout = SCHED_TIMEOUT if SCHED_TIMEOUT > 0 else 0

        r, _, _ = select.select([self.conn], [], [], timeout)
        if not r:
            return current_proc  # no input → continue with current

        data = self.conn.recv(8)
        if not data:
            return current_proc

        try:
            tid = int.from_bytes(data, byteorder='little', signed=False)
        except ValueError:
            print(f"Scheduler: invalid data {data!r}")
            return current_proc

        proc = processes.get(tid)
        if proc is not None:
            print(f"Scheduler picked TID {tid}")
            return proc

        print(f"Scheduler sent inactive TID {tid}, ignoring")
        return current_proc

    def _handle_signal(self, event: ProcessSignal):
        proc: PtraceProcess = event.process
        try:
            proc.syscall(event.signum)
        except Exception as e:
            print(f"Error arming TID {proc.pid} after signal {event.signum}: {e}")
            try:
                self.debugger.deleteProcess(proc)
            except Exception:
                pass

    def _handle_clone(self, event: NewProcessEvent):
        child = event.process
        parent = child.parent
        child_tid = child.pid

        if not self._first_clone_ignored:
            # FIRST clone is ignored
            self._first_clone_ignored = True
            self._ignored_tid = child_tid

            print(f"First clone: created TID {child_tid} — IGNORING it")

            # Detach ignored child so it runs untraced
            try:
                child.detach()
            except Exception:
                pass

            # Remove from debugger
            try:
                self.debugger.deleteProcess(child)
            except Exception:
                pass

            # Resume parent so clone() completes
            try:
                parent.syscall()
            except Exception as e:
                print(f"Error resuming parent {parent.pid} after ignored clone: {e}")
        else:
            # LATER clones are traced
            print(f"New traced thread {child_tid} (parent {parent.pid})")

            # Arm both child and parent again
            try:
                child.syscall()
            except Exception as e:
                print(f"Error arming child {child_tid}: {e}")
                try:
                    self.debugger.deleteProcess(child)
                except Exception:
                    pass

            try:
                parent.syscall()
            except Exception as e:
                print(f"Error arming parent {parent.pid}: {e}")
                try:
                    self.debugger.deleteProcess(parent)
                except Exception:
                    pass

    def _handle_exit(self, event: ProcessExit):
        dead_proc: PtraceProcess = event.process
        tid: int = dead_proc.pid
        print(f"TID {tid} exited (exitcode={event.exitcode})")

        dead_proc.detach()
        self.debugger.deleteProcess(dead_proc)

    def _handle_syscall(self, event: ProcessExecution):
        proc = event.process
        tid = proc.pid

        try:
            ip = proc.getInstrPointer()
            print(f"TID {tid} syscall-stop at {hex(ip)}")
        except Exception as e:
            print(f"Error reading IP for TID {tid}: {e}")

        # Build fresh pid->process map from debugger.list
        processes = {p.pid: p for p in self.debugger.list}

        # Scheduler decides what to run next
        current_proc = self._next(processes, proc)
        if current_proc is None or current_proc not in self.debugger.list:
            if self.is_exited():
                return
            current_proc = self.debugger.list[0]

        # Resume chosen thread
        try:
            current_proc.syscall()
        except Exception as e:
            print(f"Error arming TID {current_proc.pid}: {e}")
            try:
                self.debugger.deleteProcess(current_proc)
            except Exception:
                pass

    def is_exited(self):
        return len(self.debugger.list) == 0

    def schedule(self, pid: int):
        print(f"Attach process {pid}")
        proc0 = self.debugger.addProcess(pid, False)

        # ------------------------------------------------------------------
        # Initial state
        # ------------------------------------------------------------------
        current_proc = proc0

        # Arm the first process: run until its first event/syscall
        current_proc.syscall()

        while not self.is_exited():
            try:
                event: ProcessEvent = self.debugger.waitSyscall()
            except NewProcessEvent as event:
                self._handle_clone(event)
                continue
            except ProcessSignal as event:
                self._handle_signal(event)
                continue
            except ProcessExit as event:
                self._handle_exit(event)
                continue

            self._handle_syscall(event)

    def __del__(self):
        self.conn.close()
        self.srv.close()
        self.debugger.quit()


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

def quoted(s: str) -> str:
    return f'"{s}"'


if __name__ == "__main__":
    env = os.environ.copy()

    qemu = [
        "qemu-x86_64",
        "-g",
        "12348",
        "/nix/store/dmpq06y392i752zwhcna07kb2x5l58l5-memcached-static-x86_64-unknown-linux-musl-1.6.37/bin/memcached",
        "-p",
        "11211",
        "-t",
        "4",
        "-vv"
    ]

    proc = subprocess.Popen(qemu, env=env)
    try:
        scheduler = Scheduler()
        scheduler.schedule(proc.pid)
    except Exception as e:
        print(f"Scheduling failed: {e}")
        proc.kill()
        raise

    exit(0)

