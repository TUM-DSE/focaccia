import os
import signal
import socket
import subprocess
import sys
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

# If scheduler does not provide input within this time (seconds),
# continue running the last chosen thread.
SCHED_TIMEOUT = 0

# ----------------------------------------------------------------------
# Scheduler (non-blocking)
# ----------------------------------------------------------------------

def schedule_next_nonblocking(sock, processes, current_proc):
    timeout = SCHED_TIMEOUT if SCHED_TIMEOUT > 0 else 0

    r, _, _ = select.select([sock], [], [], timeout)
    if not r:
        return current_proc  # no input → continue with current

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
# Run proc0 until first clone, but ignore (detach) the clone child
# ----------------------------------------------------------------------

def run_until_first_clone_and_ignore_child(debugger, process):
    """
    Run until first clone event.
    Detach the cloned thread so it runs untraced.
    Return after clone child is removed.
    """
    process.cont()

    while True:
        try:
            sig = debugger.waitSignals()
            sig.process.cont(sig.signum)

        except NewProcessEvent as event:
            child = event.process
            parent = child.parent

            print(f"First clone: created TID {child.pid} — IGNORING it")

            # Detach so it runs untraced
            try:
                child.detach()
            except Exception:
                pass

            # Remove it from debugger
            debugger.deleteProcess(child)

            return  # stop after first ignored clone

        except ProcessExit as event:
            print(f"Process {event.process.pid} exited before cloning")
            raise


# ----------------------------------------------------------------------
# Main tracing logic
# ----------------------------------------------------------------------

def trace(pid, sched_socket_path):
    debugger = ptrace.debugger.PtraceDebugger()
    debugger.traceClone()
    debugger.traceFork()
    debugger.traceExec()

    print(f"Attach process {pid}")
    proc0 = debugger.addProcess(pid, False)

    # ------------------------------------------------------------------
    # Create scheduler socket
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
    # 1) Run proc0 until first clone, detach the child
    # ------------------------------------------------------------------
    run_until_first_clone_and_ignore_child(debugger, proc0)

    # ------------------------------------------------------------------
    # 2) Attach ALL threads EXCEPT the ignored clone
    # ------------------------------------------------------------------
    for tid_str in os.listdir(f"/proc/{pid}/task"):
        tid = int(tid_str)
        if tid not in debugger.dict:
            try:
                debugger.addProcess(tid, False)
            except Exception as e:
                print(f"Failed to attach TID {tid}: {e}")

    # Choose initial thread to run
    tids = list(debugger.dict.keys())
    if not tids:
        print("No traceable threads left after first clone.")
        return
    proc = debugger.dict[tids[0]]

    # ------------------------------------------------------------------
    # 3) Main loop: scheduler chooses next thread, run to syscall
    # ------------------------------------------------------------------
    while len(debugger.list) != 0:

        # possibly switch threads according to scheduler
        proc = schedule_next_nonblocking(conn, debugger.dict, proc)
        tid = proc.pid

        try:
            # run until next syscall
            proc.syscall()
            proc.waitSyscall()

            ip = proc.getInstrPointer()
            print(f"TID {tid} syscall-stop at {hex(ip)}")

        except ProcessSignal as ev:
            ev.process.cont(ev.signum)

        except ProcessExit as ev:
            print(f"Thread {ev.process.pid} exited (exitcode={ev.exitcode})")

            try:
                ev.process.detach()
            except Exception:
                pass

            debugger.deleteProcess(ev.process)

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

        # handle new threads (they *are* traced normally)
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
        "-g",
        "12348",
        "./reproducers/issue-508.static-musl.rr.out/mmap_clone_4_issue-508.static-musl.out"
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

