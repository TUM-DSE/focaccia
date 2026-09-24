"""Standalone LLDB API experiment; never imports the production tracer.

Live use requires an authorized same-ISA Linux runner, same-user ptrace and
process memory access. No host settings are changed. RR is deliberately absent.
The fake-only flake check establishes harness behavior, not native support.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time


SCHEMA = "focaccia-native-terminal-observation-v1"
CAPABILITIES = [
    "native same-ISA Linux execution",
    "same-user ptrace",
    "process_vm_readv/process_vm_writev",
]


def observation(api, process, state):
    """Read only event/status APIs; no frames, PCs, registers or memory."""
    record = {"state": state, "state_name": api.SBDebugger.StateAsCString(state)}
    if state == api.eStateExited:
        record.update(
            exit_status=process.GetExitStatus(), exit_description=process.GetExitDescription()
        )
    elif state in (api.eStateStopped, api.eStateCrashed):
        record["threads"] = [
            {
                "tid": thread.GetThreadID(),
                "stop_reason": thread.GetStopReason(),
                "stop_description": thread.GetStopDescription(4096),
                "stop_data": [
                    thread.GetStopReasonDataAtIndex(i)
                    for i in range(thread.GetStopReasonDataCount())
                ],
            }
            for thread in process
        ]
    return record


def advance_observed_state(api, process, state, emit, last_stop_id=None):
    """Advance a live stop once; only an exited state establishes termination."""
    if state == api.eStateExited:
        return True, last_stop_id
    if state in (api.eStateDetached, api.eStateInvalid):
        raise RuntimeError("Process lost before exit")
    if state in (api.eStateStopped, api.eStateCrashed):
        # A queued initial stop may arrive after Launch already exposed that stop.
        # Do not resume a running process or resume the same stop twice.
        if process.GetState() != state:
            return False, last_stop_id
        stop_id = process.GetStopID()
        if stop_id != last_stop_id:
            result = process.Continue()
            emit({"continue_error": result.GetCString(), "continued_stop_id": stop_id})
            if not result.Success():
                raise RuntimeError("LLDB continue failed")
            last_stop_id = stop_id
    return False, last_stop_id


def observe(debugger, binary, output):
    """Invoked inside the flake LLDB, bounded externally by the harness."""
    import lldb

    def emit(record):
        stream.write(json.dumps(record) + "\n")
        stream.flush()

    with Path(output).open("x", encoding="utf-8") as stream:
        emit({"schema": SCHEMA, "lldb_version": lldb.SBDebugger.GetVersionString()})
        debugger.SetAsync(True)
        target = debugger.CreateTarget(binary)
        if not target.IsValid():
            raise RuntimeError("Invalid LLDB target")
        error = lldb.SBError()
        process = target.Launch(
            debugger.GetListener(), [], None, None, None, None, None, 0, True, error
        )
        emit({"launch_error": error.GetCString()})
        if not error.Success() or not process.IsValid():
            raise RuntimeError("LLDB launch failed")
        # The debugger UI also consumes its default listener (and prints stops).
        # Subscribe an independent queue before resuming so it cannot take ours.
        listener = lldb.SBListener("terminal-observation")
        requested = lldb.SBProcess.eBroadcastBitStateChanged
        subscribed = process.GetBroadcaster().AddListener(listener, requested)
        emit({"requested_event_mask": requested, "subscribed_event_mask": subscribed})
        if subscribed & requested != requested:
            raise RuntimeError("Unable to subscribe to process state events")
        # Stop before delivering SIGTERM, retain its stop reason, then pass it.
        signals = process.GetUnixSignals()
        number = signals.GetSignalNumberFromName("SIGTERM")
        configured = [
            signals.SetShouldStop(number, True),
            signals.SetShouldSuppress(number, False),
            signals.SetShouldNotify(number, True),
        ]
        emit({"signal_number": number, "signal_policy_results": configured})
        if number < 0 or not all(configured):
            raise RuntimeError("Unable to configure explicit SIGTERM delivery")
        # Launch(stop_at_entry=True) may consume the initial stopped event.
        # Observe the public state once rather than waiting for a second event.
        state = process.GetState()
        emit({"source": "after-launch", **observation(lldb, process, state)})
        exited, last_stop_id = advance_observed_state(lldb, process, state, emit)
        if exited:
            return
        next_poll = time.monotonic()
        while True:
            event = lldb.SBEvent()
            received = listener.WaitForEvent(1, event)
            is_process_event = received and lldb.SBProcess.EventIsProcessEvent(event)
            record = {}
            if received:
                description = lldb.SBStream()
                event.GetDescription(description)
                record = {"event_type": event.GetType(), "event_description": description.GetData()}
            if is_process_event:
                state = lldb.SBProcess.GetStateFromEvent(event)
                record.update(observation(lldb, process, state))
                record["restarted"] = lldb.SBProcess.GetRestartedFromEvent(event)
                emit(record)
                if not record["restarted"]:
                    exited, last_stop_id = advance_observed_state(
                        lldb, process, state, emit, last_stop_id
                    )
                    if exited:
                        return
            else:
                if received:
                    emit(record)
                # Diagnostic fallback: observe actual state, never infer exit from
                # silence. At most one poll/second; run_command's deadline bounds
                # the entire process even if LLDB blocks or remains running.
                now = time.monotonic()
                if now >= next_poll:
                    next_poll = now + 1
                    state = process.GetState()
                    emit(
                        {
                            "source": "state-poll",
                            "stop_id": process.GetStopID(),
                            **observation(lldb, process, state),
                        }
                    )
                    exited, last_stop_id = advance_observed_state(
                        lldb, process, state, emit, last_stop_id
                    )
                    if exited:
                        return


def run_command(command, log, timeout):
    """Own the debugger process group and retain raw logs even on timeout."""
    with log.open("x", encoding="utf-8") as stream:
        with subprocess.Popen(
            command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True
        ) as process:
            try:
                return {"returncode": process.wait(timeout=timeout), "timeout": False}
            except subprocess.TimeoutExpired:
                return {"returncode": None, "timeout": True}
            finally:
                # Also clean up inferior/debugserver descendants after LLDB exits.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lldb", required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be finite and positive")
    root = args.run_directory.resolve()
    commands = {}
    binaries = {}
    for case in ("exit0", "exit7", "fatal-signal"):
        binary = (args.fixtures / case).resolve()
        binaries[case] = {
            "path": str(binary),
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
        script = (
            f"script import sys; sys.path.insert(0, {str(Path(__file__).parent)!r}); "
            f"import native_terminal_observation as probe; "
            f"probe.observe(lldb.debugger, {str(binary)!r}, "
            f"{str(root / (case + '.jsonl'))!r})"
        )
        commands[case] = [args.lldb, "--no-lldbinit", "--batch", "-o", script]
    plan = {
        "schema": SCHEMA,
        "capabilities": CAPABILITIES,
        "commands": commands,
        "binaries": binaries,
        "timeout_seconds": args.timeout,
        "expected_fixture_actions": {
            "exit0": "_exit(0)",
            "exit7": "_exit(7)",
            "fatal-signal": "raise(SIGTERM)",
        },
        "scope": "raw observation only; not whole-program validation",
    }
    if args.dry_run:
        print(json.dumps(plan, indent=2))
        return 0
    root.mkdir(parents=True, exist_ok=False)
    (root / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    results = {}
    for case, command in commands.items():
        started = time.monotonic()
        result = {"returncode": None, "timeout": False, "exit_observed": False}
        try:
            result.update(run_command(command, root / (case + ".log"), args.timeout))
            evidence = root / (case + ".jsonl")
            rows = (
                [json.loads(line) for line in evidence.read_text().splitlines()]
                if evidence.exists()
                else []
            )
            # LLDB batch can exit zero after a Python exception. Require exit evidence.
            result["exit_observed"] = any(
                isinstance(row, dict) and "exit_status" in row for row in rows
            )
        except (OSError, ValueError) as error:
            result["infrastructure_error"] = str(error)
        result["elapsed_seconds"] = time.monotonic() - started
        results[case] = result
        (root / "result.json").write_text(
            json.dumps({"schema": SCHEMA, "cases": results}, indent=2) + "\n"
        )
    return int(
        any(
            r["timeout"] or r["returncode"] != 0 or not r["exit_observed"] for r in results.values()
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
