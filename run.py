import os
import signal
import socket
import subprocess
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
    """
    processes: dict[tid] -> PtraceProcess
    current_proc: PtraceProcess or None
    """
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

    proc = processes.get(tid)
    if proc is not None:
        print(f"Scheduler picked TID {tid}")
        return proc

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

    # ignore-first-clone state
    first_clone_ignored = False
    ignored_tid = None

    # Arm first process: run until its first event/syscall
    current_proc.syscall()

    # ------------------------------------------------------------------
    # Global event loop
    # ------------------------------------------------------------------
    while debugger.list:
        try:
            event = debugger.waitSyscall()

        # --------------------------------------------------------------
        # New process / thread via clone/fork/vfork
        # --------------------------------------------------------------
        except NewProcessEvent as ev:
            child = ev.process
            parent = child.parent
            child_tid = child.pid

            if not first_clone_ignored:
                # FIRST clone is ignored
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
                try:
                    parent.syscall()
                except Exception as e:
                    print(f"Error resuming parent {parent.pid} after ignored clone: {e}")
            else:
                # LATER clones are traced
                print(f"New traced thread {child_tid} (parent {parent.pid})")

                # Both child and parent should be armed again
                try:
                    child.syscall()
                except Exception as e:
                    print(f"Error arming child {child_tid}: {e}")
                    try:
                        debugger.deleteProcess(child)
                    except Exception:
                        pass

                try:
                    parent.syscall()
                except Exception as e:
                    print(f"Error arming parent {parent.pid}: {e}")
                    try:
                        debugger.deleteProcess(parent)
                    except Exception:
                        pass

            continue

        # --------------------------------------------------------------
        # Signal delivered to a traced task
        # --------------------------------------------------------------
        except ProcessSignal as ev:
            proc = ev.process
            try:
                proc.syscall(ev.signum)
            except Exception as e:
                print(f"Error arming TID {proc.pid} after signal {ev.signum}: {e}")
                try:
                    debugger.deleteProcess(proc)
                except Exception:
                    pass
            continue

        # --------------------------------------------------------------
        # A traced task exited
        # --------------------------------------------------------------
        except ProcessExit as ev:
            dead_proc = ev.process
            tid = dead_proc.pid
            print(f"TID {tid} exited (exitcode={ev.exitcode})")

            try:
                dead_proc.detach()
            except Exception:
                pass

            try:
                debugger.deleteProcess(dead_proc)
            except Exception:
                pass

            if not debugger.list:
                break

            # Choose a new current_proc and arm it
            current_proc = debugger.list[0]
            try:
                current_proc.syscall()
            except Exception as e:
                print(f"Error arming new current TID {current_proc.pid}: {e}")
                try:
                    debugger.deleteProcess(current_proc)
                except Exception:
                    pass
            continue

        # --------------------------------------------------------------
        # NORMAL SYSCALL STOP
        # --------------------------------------------------------------
        proc = event.process
        tid = proc.pid

        if tid == ignored_tid:
            # Should not happen; just log and continue
            print(f"WARNING: ignored TID {tid} hit a syscall-stop")
        else:
            try:
                ip = proc.getInstrPointer()
                print(f"TID {tid} syscall-stop at {hex(ip)}")
            except Exception as e:
                print(f"Error reading IP for TID {tid}: {e}")

        # Build a fresh pid->process map from the debugger
        processes = {p.pid: p for p in debugger.list}

        # Scheduler decides what to run next
        current_proc = schedule_next_nonblocking(conn, processes, proc)
        if current_proc is None or current_proc not in debugger.list:
            # Fallback: pick any alive one
            if not debugger.list:
                break
            current_proc = debugger.list[0]

        # Resume chosen thread
        try:
            current_proc.syscall()
        except Exception as e:
            print(f"Error arming TID {current_proc.pid}: {e}")
            try:
                debugger.deleteProcess(current_proc)
            except Exception:
                pass
            # We don't immediately re-arm here; next loop iteration will
            # pick another process (if any) and arm it.

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

