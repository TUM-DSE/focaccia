import signal
import threading
from typing import cast

import pytest

from focaccia.native import spec_target
from focaccia.native.lldb_target import ConcreteExecutionError, LLDBLocalTarget


class Timer:
    def __init__(self, seconds, callback):
        self.seconds, self.callback = seconds, callback
        self.cancelled = False

    def start(self):
        pass

    def cancel(self):
        self.cancelled = True


def target_stub():
    target = object.__new__(spec_target.NativeSpecTarget)
    target._closed = False
    # Presence sentinel; no debugger operation is performed by timeout arming.
    target._target = cast(LLDBLocalTarget, object())
    target.pid = 123
    target._timeout_lock = threading.Lock()
    target._timeout_timer = None
    target._timeout_pidfd = None
    target._timed_out = False
    target._stdout = target._stderr = b""
    target._stdout_path = target._stderr_path = "/nonexistent-native-output"
    target._output_dir = None
    return target


def test_timeout_uses_owned_pidfd_and_close_disarms_callback(monkeypatch):
    target = target_stub()
    sent, closed = [], []
    monkeypatch.setattr(spec_target.threading, "Timer", Timer)
    monkeypatch.setattr(spec_target.os, "pidfd_open", lambda pid: 987 if pid == 123 else None)
    monkeypatch.setattr(spec_target.signal, "pidfd_send_signal", lambda fd, sig: sent.append((fd, sig)))
    monkeypatch.setattr(spec_target.os, "close", closed.append)
    target.set_timeout(5)
    # set_timeout uses the monkeypatched Timer fixture above.
    timer = cast(Timer, target._timeout_timer)
    timer.callback()
    assert sent == [(987, signal.SIGKILL)]
    assert target._timed_out
    with pytest.raises(ConcreteExecutionError, match="already armed"):
        target.set_timeout(10)
    target._target = None  # The mock does not own a real LLDB process.
    target.close()
    timer.callback()
    assert timer.cancelled
    assert closed == [987]
    assert sent == [(987, signal.SIGKILL)]


def test_expired_pidfd_never_targets_a_reused_pid(monkeypatch):
    target = target_stub()
    monkeypatch.setattr(spec_target.threading, "Timer", Timer)
    monkeypatch.setattr(spec_target.os, "pidfd_open", lambda pid: 987)

    def exited(fd, sig):
        raise ProcessLookupError()

    monkeypatch.setattr(spec_target.signal, "pidfd_send_signal", exited)
    target.set_timeout(5)
    cast(Timer, target._timeout_timer).callback()
    assert not target._timed_out


@pytest.mark.parametrize("seconds", [0, -1, float("nan"), float("inf")])
def test_timeout_rejects_invalid_limits(seconds):
    with pytest.raises(ValueError, match="finite and positive"):
        target_stub().set_timeout(seconds)
