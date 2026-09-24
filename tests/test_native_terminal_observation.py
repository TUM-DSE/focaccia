"""Fake-only checks: no LLDB import, debugger, RR or native fixture execution."""

import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest


probe = SimpleNamespace(
    **runpy.run_path(str(Path(__file__).parent / "probes/native_terminal_observation.py"))
)


def test_exit_observation_never_accesses_threads_or_registers():
    class Exited:
        def GetExitStatus(self):
            return 7

        def GetExitDescription(self):
            return "raw exit description"

        def __iter__(self):
            raise AssertionError("post-exit thread access")

    api = SimpleNamespace(
        eStateExited=10, SBDebugger=SimpleNamespace(StateAsCString=lambda state: "exited")
    )
    assert probe.observation(api, Exited(), 10) == {
        "state": 10,
        "state_name": "exited",
        "exit_status": 7,
        "exit_description": "raw exit description",
    }


def test_signal_stop_preserves_raw_reason_without_inventing_exit():
    thread = SimpleNamespace(
        GetThreadID=lambda: 123,
        GetStopReason=lambda: 5,
        GetStopDescription=lambda size: "signal SIGTERM",
        GetStopReasonDataCount=lambda: 1,
        GetStopReasonDataAtIndex=lambda i: 15,
    )
    api = SimpleNamespace(
        eStateExited=10,
        eStateStopped=5,
        eStateCrashed=8,
        SBDebugger=SimpleNamespace(StateAsCString=lambda s: "stopped"),
    )
    row = probe.observation(api, [thread], 5)
    assert row["threads"][0]["stop_data"] == [15]
    assert row["threads"][0]["stop_description"] == "signal SIGTERM"
    assert "exit_status" not in row


def arguments(tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    for case in ("exit0", "exit7", "fatal-signal"):
        (fixtures / case).write_bytes(b"not executable")
    return [
        "--lldb",
        "/never/execute/lldb",
        "--fixtures",
        str(fixtures),
        "--run-directory",
        str(tmp_path / "run"),
    ]


def test_dry_run_is_nonexecuting_and_records_capabilities(tmp_path, capsys):
    import json

    assert probe.main(arguments(tmp_path) + ["--dry-run"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert "same-user ptrace" in plan["capabilities"]
    assert set(plan["commands"]) == {"exit0", "exit7", "fatal-signal"}
    assert not (tmp_path / "run").exists()


def test_existing_directory_is_never_overwritten(tmp_path):
    args = arguments(tmp_path)
    (tmp_path / "run").mkdir()
    with pytest.raises(FileExistsError):
        probe.main(args)


@pytest.mark.parametrize("timeout", ["nan", "inf", "0", "-1"])
def test_invalid_timeout_rejected(tmp_path, timeout):
    with pytest.raises(SystemExit):
        probe.main(arguments(tmp_path) + ["--timeout", timeout])


def test_zero_lldb_exit_without_terminal_evidence_is_failure(tmp_path, monkeypatch):
    args = arguments(tmp_path)
    monkeypatch.setitem(
        probe.main.__globals__, "run_command", lambda *args: {"returncode": 0, "timeout": False}
    )
    assert probe.main(args) == 1


def test_timeout_kills_owned_process_group(tmp_path, monkeypatch):
    module = probe.run_command.__globals__
    kills = []

    class Process:
        pid = 123

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def wait(self, timeout=None):
            if timeout is not None:
                raise module["subprocess"].TimeoutExpired("lldb", timeout)
            return -9

    monkeypatch.setattr(module["subprocess"], "Popen", lambda *a, **kw: Process())
    monkeypatch.setattr(module["os"], "killpg", lambda pid, sig: kills.append((pid, sig)))
    assert probe.run_command(["lldb"], tmp_path / "raw.log", 1)["timeout"]
    assert kills == [(123, module["signal"].SIGKILL)]


@pytest.mark.parametrize("delivery", ["events", "silent", "progress"])
def test_consumed_initial_stop_is_resumed_before_waiting(tmp_path, monkeypatch, delivery):
    import json
    import sys

    error = SimpleNamespace(GetCString=lambda: None, Success=lambda: True)
    signals = SimpleNamespace(
        GetSignalNumberFromName=lambda name: 15,
        SetShouldStop=lambda *args: True,
        SetShouldSuppress=lambda *args: True,
        SetShouldNotify=lambda *args: True,
    )

    class Process:
        state = 5
        continues = 0

        def IsValid(self):
            return True

        def GetUnixSignals(self):
            return signals

        def GetBroadcaster(self):
            return SimpleNamespace(AddListener=lambda listener, mask: mask)

        def GetState(self):
            return self.state

        def GetStopID(self):
            return self.continues + 1

        def __iter__(self):
            if self.state == 10:
                raise AssertionError("post-exit thread access")
            return iter(())

        def Continue(self):
            self.continues += 1
            self.state = 10 if delivery == "events" or self.continues == 2 else 5
            return error

        def GetExitStatus(self):
            return 7

        def GetExitDescription(self):
            return "exit 7"

    process = Process()

    def wait(seconds, event):
        assert process.continues >= 1, "initial stop consumed; waiting would time out"
        return delivery != "silent"

    api = SimpleNamespace(
        eStateStopped=5,
        eStateCrashed=8,
        eStateExited=10,
        eStateDetached=9,
        eStateInvalid=0,
        SBDebugger=SimpleNamespace(
            GetVersionString=lambda: "fake LLDB", StateAsCString=lambda state: str(state)
        ),
        SBError=lambda: error,
        SBEvent=lambda: SimpleNamespace(GetDescription=lambda stream: None, GetType=lambda: 1),
        SBStream=lambda: SimpleNamespace(GetData=lambda: "exited event"),
        SBListener=lambda name: SimpleNamespace(WaitForEvent=wait),
        SBProcess=SimpleNamespace(
            eBroadcastBitStateChanged=1,
            EventIsProcessEvent=lambda event: delivery == "events",
            GetStateFromEvent=lambda event: 10,
            GetRestartedFromEvent=lambda event: False,
        ),
    )
    debugger = SimpleNamespace(
        SetAsync=lambda value: None,
        GetListener=lambda: SimpleNamespace(WaitForEvent=wait),
        CreateTarget=lambda binary: SimpleNamespace(
            IsValid=lambda: True, Launch=lambda *args: process
        ),
    )
    monkeypatch.setitem(sys.modules, "lldb", api)
    clock = iter(range(100))
    monkeypatch.setattr(probe.observe.__globals__["time"], "monotonic", lambda: next(clock))
    output = tmp_path / "events.jsonl"
    probe.observe(debugger, "/fake/exit7", str(output))
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    initial = next(row for row in rows if row.get("source") == "after-launch")
    assert initial["state"] == 5 and "exit_status" not in initial
    assert rows[-1]["exit_status"] == 7
    assert process.continues == (1 if delivery == "events" else 2)
    assert any(row.get("subscribed_event_mask") == 1 for row in rows)
    if delivery != "events":
        polls = [row for row in rows if row.get("source") == "state-poll"]
        assert polls[0]["state"] == 5 and polls[0]["stop_id"] == 2
        assert "exit_status" not in polls[0]
        assert polls[-1]["state"] == 10


def test_delayed_initial_stop_does_not_resume_same_stop_twice():
    calls = []
    api = SimpleNamespace(
        eStateExited=10, eStateDetached=9, eStateInvalid=0, eStateStopped=5, eStateCrashed=8
    )
    error = SimpleNamespace(GetCString=lambda: None, Success=lambda: True)
    process = SimpleNamespace(
        GetState=lambda: 5, GetStopID=lambda: 1, Continue=lambda: calls.append("continue") or error
    )
    exited, stop_id = probe.advance_observed_state(api, process, 5, lambda row: None)
    assert not exited and stop_id == 1
    assert probe.advance_observed_state(api, process, 5, lambda row: None, stop_id) == (False, 1)
    assert calls == ["continue"]


@pytest.mark.parametrize("state", [0, 9])
def test_initial_process_loss_is_not_termination(state):
    api = SimpleNamespace(eStateExited=10, eStateDetached=9, eStateInvalid=0)
    with pytest.raises(RuntimeError, match="lost before exit"):
        probe.advance_observed_state(api, object(), state, lambda row: None)
