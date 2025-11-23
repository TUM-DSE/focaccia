import os
import signal
import socket
import subprocess
import sys

import ptrace.debugger
from ptrace.debugger import (
    ProcessSignal,
    ProcessExit,
    NewProcessEvent,
)


# -------- scheduler via unix socket --------

def read_next_tid(sock, processes):
    """
    Read the next thread ID to schedule from a controller over a socket.
    Blocks until a valid TID is received.
    """
    while True:
        data = sock.recv(64)
        if not data:
            continue  # ignore empty reads

        try:
            tid = int(data.strip())
        except ValueError:
            print(f"Invalid scheduler value: {data!r}")
            continue

        if tid in processes:
            print(f"Scheduler selected TID {tid}")
            return processes[tid]

        print(f"TID {tid} not active, waiting for a valid one …")


# -------- wait until first clone --------

def run_until_first_clone(debugger, process):
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


# -------- main tracer --------

def trace(pid, sched_socket_path):
    debugger = ptrace.debugger.PtraceDebugger()

    debugger.traceClone()
    debugger.traceFork()
    debugger.traceExec()

    print(f"Attach process {pid}")
    proc0 = debugger.addProcess(pid, False)

    # Create listening scheduling socket
    if os.path.exists(sched_socket_path):
        os.unlink(sched_socket_path)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sched_socket_path)
    srv.listen(1)

    print(f"Waiting for scheduler connection on {sched_socket_path}")
    conn, _ = srv.accept()
    print("Scheduler connected")

    # 1) run until clone
    run_until_first_clone(debugger, proc0)

    # 2) attach all existing threads after clone
    for tid_str in os.listdir(f"/proc/{pid}/task"):
        tid = int(tid_str)
        if tid not in debugger.dict:
            try:
                debugger.addProcess(tid, False)
            except Exception as e:
                print(f"Failed to attach TID {tid}: {e}")

    # 3) main loop: scheduler picks TID → run it to next syscall
    while len(debugger.list) != 0:
        proc = read_next_tid(conn, debugger.dict)
        tid = proc.pid

        try:
            proc.syscall()         # continue until syscall entry/exit
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

        except Exception as e:
            print(f"TID {tid} exception: {e}")
            try:
                proc.detach()
            except Exception:
                pass
            debugger.deleteProcess(proc)

        # detect new threads
        for p in list(debugger.list):
            t = p.pid
            if t not in debugger.dict:
                debugger.dict[t] = p

    conn.close()
    srv.close()
    debugger.quit()


# -------- entry point --------

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

