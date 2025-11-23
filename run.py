import os
import signal
import socket
import subprocess
import sys
import termios
import tty
import select

import ptrace.debugger
from ptrace.debugger import (
    ProcessSignal,
    ProcessExit,
    NewProcessEvent,
)

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

# Scheduler timeout in seconds.
# 0 => purely non-blocking (never waits for scheduler input).
SCHED_TIMEOUT = 0.1


# ----------------------------------------------------------------------
# Scheduler logic via non-blocking UNIX socket
# ----------------------------------------------------------------------

def schedule_next_nonblocking(sock, processes, current_proc):
    """
    Try to read the next TID from 'sock' within SCHED_TIMEOUT.
    If valid and present in 'processes', return that PtraceProcess.
    Otherwise return current_proc.
    """

    # Handle timeout = 0 (purely non-blocking)
    timeout = SCHED_TIMEOUT if SCHED_TIMEOUT > 0 else 0

    r, _, _ = select.select([sock], [], [], timeout)
    if not r:
        # No scheduler input
        return current_proc

    data = sock.recv(64)
    if not data:
        return current_proc

    try:
        tid = int(data.strip())
    except ValueError:
        print(f"Scheduler sent invalid data: {data!r}")
        return current_proc

    if tid in processes:
        print(f"Scheduler selected TID {tid}")
        return processes[tid]

    print(f"TID {tid} not active; ignoring")
    return current_proc


# ----------------------------------------------------------------------
# First clone handling
# ----------------------------------------------------------------------

def run_until_first_clone(debugger, process):
    """
    Continue execution until the first clone (new thread/process) event occurs.
    """

    process.cont()

    while True:
        try:
            sig = debugger.waitSignals()
            sig.process.cont(sig.signum)

        except NewProcessEvent as event:
            new_proc = event.process
            print(f"First clone: TID {new_proc.pid}")
            return

        except ProcessExit as event:
            print(f"Process {event.process.pid} exited before cloning")
            raise


# ----------------------------------------------------------------------
# Main Trace Function
# ----------------------------------------------------------------------

def trace(pid, sched_socket_path):
    debugger = ptrace.debugger.PtraceDebugger()

    debugger.traceClone()
    debugger.traceFork()
    debugger.traceExec()

    print(f"Attach process {pid}")
    proc0 = debugger.addProcess(pid, False)

    # ------------------------------------------------------------------
    # Create Unix scheduling socket
    # ------------------------------------------------------------------
    if os.path.exists(sched_socket_path):
        os.unlink(sched_socket_path)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sched_socket_path)
    srv.listen(1)

    print(f"Waiting for scheduler connection on {sched_socket_path}")
    conn, _ = srv.accept()
    print("Scheduler connected")

    # ------------------------------------------------------------------
    # 1) Run until the first clone happens
    # ------------------------------------------------------------------
    run_until_first_clone(debugger, proc0)

    # ------------------------------------------------------------------
    # 2) Attach all threads in the process
    # ------------------------------------------------------------------
    for tid_str in os.listdir(f"/proc/{pid}/task"):
        tid = int(tid_str)
        if tid not in debugger.dict:
            try:
                debugger.addProcess(tid, False)
            except Exception as e:
                print(f"Failed to attach TID {tid}: {e}")

    # Choose an initial thread arbitrarily
    tids = list(debugger.dict.keys())
    if not tids:
        print("No threads to trace")
        return
    proc = debugger.dict[tids[0]]

    # ------------------------------------------------------------------
    # 3) Main scheduling / syscall loop
    # ------------------------------------------------------------------
    while len(debugger.list) != 0:
        # Obtain next thread to schedule (possibly the same one)
        proc = schedule_next_nonblocking(conn, debugger.dict, proc)
        tid = proc.pid

        try:
            # Continue execution until next syscall entry or exit
            proc.syscall()
            proc.waitSyscall()

            ip = proc.getInstrPointer()
            print(f"TID {tid} syscall-stop at {hex(ip)}")

        except ProcessSignal as ev:
            # Forward non-TRAP signals
            ev.process.cont(ev.signum)

        except ProcessExit as ev:
            print(f"Thread {ev.process.pid} exited (exitcode={ev.exitcode})")

            try:
                ev.process.detach()
            except Exception:
                pass

            debugger.deleteProcess(ev.process)

            # If the thread was the current one, pick another
            if proc not in debugger.list and len(debugger.list) > 0:
                proc = debugger.list[0]

        except Exception as e:
            print(f"TID {tid} exception: {e}")

            try:
                proc.detach()
            except Exception:
                pass

            debugger.deleteProcess(proc)

            if len(debugger.list) > 0:
                proc = debugger.list[0]

        # Attach new threads created while tracing
        for p in list(debugger.list):
            t = p.pid
            if t not in debugger.dict:
                debugger.dict[t] = p

    conn.close()
    srv.close()
    debugger.quit()


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------

def quoted(s: str) -> str:
    return f'"{s}"'


if __name__ == "__main__":
    env = os.environ.copy()

    qemu = [
        "qemu-x86_64",
        "/nix/store/dmpq06y392i752zwhcna07kb2x5l58l5-memcached-static-x86_64-unknown-linux-musl-1.6.37/bin/memcached",
        "-p", "11211",
        "-t", "4",
        "-vv",
    ]

    sched_path = "/tmp/memcached_scheduler.sock"

    proc = subprocess.Popen(qemu, env=env)
    try:
        trace(proc.pid, sched_path)
    except Exception as e:
        print(f"Got exception: {e}")
        proc.kill()
        exit(2)

    exit(0)

