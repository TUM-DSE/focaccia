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
        print(f"Scheduler: invalid data {data!r}")
        return current_proc

    if tid in processes:
        print(f"Scheduler picked TID {tid}")
        return processes[tid]

    print(f"Scheduler sent inactive TID {tid}, ignoring")
    return current_proc


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
    # Prime the very first thread
    # ------------------------------------------------------------------
    current_proc = proc0

    # Arm the first process: run until its first event/syscall
    current_proc.syscall()

    # Flag for ignoring the first clone
    ignored_tid = None
    first_clone_ignored = False

    # ------------------------------------------------------------------
    # Global event loop — always resume one tracee after every event
    # ------------------------------------------------------------------
    while debugger.list:
        try:
            event = debugger.waitSyscall()

        # --------------------------------------------------------------
        # New traced process (clone/fork/vfork)
        # --------------------------------------------------------------
        except NewProcessEvent as ev:
            child = ev.process
            parent = child.parent
            child_tid = child.pid

            if not first_clone_ignored:
                # FIRST CLONE is ignored completely
                first_clone_ignored = True
                ignored_tid = child_tid

                print(f"First clone: created TID {child_tid} — IGNORING it")

                # Detach ignored child so it runs untraced
                try:
                    child.detach()
                except Exception:
                    pass

                # Remove from debugger
                debugger.deleteProcess(child)

                # Resume parent so clone() completes
                parent.syscall()

            else:
                # LATER CLONES ARE TRACED
                print(f"New traced thread {child_tid} (parent {parent.pid})")

                debugger.dict[child_tid] = child

                # Arm both child and parent
                child.syscall()
                parent.syscall()

            continue

        # --------------------------------------------------------------
        # When a process gets a non-SIGTRAP signal
        # --------------------------------------------------------------
        except ProcessSignal as ev:
            ev.process.syscall(ev.signum)

            continue

        # --------------------------------------------------------------
        # A traced thread died
        # --------------------------------------------------------------
        except ProcessExit as ev:
            dead_proc = ev.process
            tid = dead_proc.pid
            print(f"TID {tid} exited (exitcode={ev.exitcode})")

            try:
                dead_proc.detach()
            except Exception:
                pass

            debugger.deleteProcess(dead_proc)

            # If the one that died was the current process, pick another
            if debugger.list:
                current_proc = debugger.list[0]

            continue

        # --------------------------------------------------------------
        # NORMAL SYSCALL STOP
        # --------------------------------------------------------------
        proc = event.process
        tid = proc.pid

        if tid == ignored_tid:
            # Should never happen (ignored child not traced)
            print(f"WARNING: ignored TID {tid} hit a syscall-stop??")
        else:
            ip = proc.getInstrPointer()
            print(f"TID {tid} syscall-stop at {hex(ip)}")

        # Ensure all traced threads appear in debugger.dict
        for p in debugger.list:
            t = p.pid
            if t not in debugger.dict:
                debugger.dict[t] = p

        # Ask scheduler which thread to run next
        current_proc = schedule_next_nonblocking(conn, debugger.dict, proc)

        if current_proc not in debugger.list:
            # If scheduler picked a dead or detached thread, pick any alive one
            current_proc = debugger.list[0]

        # Resume chosen thread
        current_proc.syscall()

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
        "/nix/store/dmpq06y392i752zwhcna07kb2x5l58l5-memcached-static-x86_64-unknown-linux-musl-1.6.37/bin/memcached",
        "-p",
        "11211",
        "-t",
        "4",
        "-vv"
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

