"""Owned GDB process observations; no debugger or emulator is launched."""
import sys
from types import SimpleNamespace

import pytest

from focaccia.execution import ExecutionState
from test_gdb_program_state import load_target_module


class Registry:
    def __init__(self):
        self.handlers = []

    def connect(self, handler):
        self.handlers.append(handler)

    def disconnect(self, handler):
        self.handlers.remove(handler)

    def emit(self, event):
        for handler in self.handlers:
            handler(event)


@pytest.fixture
def backend(monkeypatch):
    module = load_target_module(monkeypatch)
    gdb = module.gdb
    thread = SimpleNamespace(is_running=lambda: False, is_stopped=lambda: True)
    inferior = SimpleNamespace(
        is_valid=lambda: True, threads=lambda: [thread],
        architecture=lambda: SimpleNamespace(name=lambda: "i386:x86-64"),
        progspace=SimpleNamespace(filename="guest"),
    )
    frame = SimpleNamespace(read_register=lambda name: 0x1000, is_valid=lambda: True)
    gdb.selected_inferior = lambda: inferior
    gdb.selected_frame = lambda: frame
    gdb.selected_thread = lambda: thread
    gdb.events = SimpleNamespace(stop=Registry(), exited=Registry())
    gdb.StopEvent = type("StopEvent", (), {})
    gdb.SignalEvent = type("SignalEvent", (gdb.StopEvent,), {})
    gdb.TYPE_CODE_INT = 1
    values = {}
    gdb.set_convenience_variable = lambda key, value: values.update({key: value})
    gdb.convenience_variable = lambda key: values.get(key)
    gdb.execute = lambda *args, **kwargs: None
    connector = module.GDBServerConnector("fake:123")
    yield module, connector, inferior, frame, values
    connector.close()
    sys.modules.pop("focaccia.qemu.target", None)


class SignalValue:
    def __init__(self, value, code=1):
        self.value = value
        self.type = SimpleNamespace(code=code)

    def __int__(self):
        return self.value


def exit_event(module, inferior, **fields):
    module.gdb.events.exited.emit(SimpleNamespace(inferior=inferior, **fields))


@pytest.mark.parametrize("status", [0, 7, 15, 255])
def test_owned_exit_status(backend, status):
    module, connector, inferior, frame, _ = backend
    frame.read_register = lambda name: pytest.fail("post-exit register read")
    exit_event(module, inferior, exit_code=status)
    outcome = connector.execution_outcome()
    assert connector.is_exited()
    assert outcome.exit_status == status
    assert outcome.termination_signal is None
    assert outcome.terminal_known
    with pytest.raises(RuntimeError, match="exited"):
        connector.current_state()
    with pytest.raises(RuntimeError, match="exited"):
        connector._step()


def test_signal_stop_is_not_termination(backend):
    module, connector, inferior, _, _ = backend
    event = module.gdb.SignalEvent()
    event.stop_signal = "SIGTERM"
    event.inferior_thread = SimpleNamespace(inferior=inferior)
    module.gdb.events.stop.emit(event)
    outcome = connector.execution_outcome()
    assert outcome.state is ExecutionState.STOPPED
    assert outcome.stop_signal == 15
    assert not outcome.terminal_known
    assert connector.terminal_reason().pc == 0x1000
    exit_event(module, inferior)
    assert connector.execution_outcome().state is ExecutionState.EXITED
    assert not connector.execution_outcome().terminal_known


@pytest.mark.parametrize("pending", ["SIGILL", "SIGTRAP"])
def test_pending_guest_signal_is_delivered_once_and_records_real_termination(
    backend, pending
):
    module, connector, inferior, frame, _ = backend
    event = module.gdb.SignalEvent()
    event.stop_signal = pending
    event.inferior_thread = SimpleNamespace(inferior=inferior)
    module.gdb.events.stop.emit(event)
    number = getattr(module.signal, pending)
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        frame.read_register = lambda name: pytest.fail("post-exit register read")
        exit_event(module, inferior)

    module.gdb.execute = execute
    outcome = connector.deliver_pending_guest_signal_once()

    assert commands == [f"signal {pending}"]
    assert outcome.termination_signal == number
    assert outcome.terminal_known
    reason = connector.terminal_reason()
    assert reason.delivered
    assert reason.outcome == outcome
    with pytest.raises(RuntimeError, match="already delivered"):
        connector.deliver_pending_guest_signal_once()


def test_pending_signal_handler_can_exit_normally(backend):
    module, connector, inferior, _, _ = backend
    event = module.gdb.SignalEvent()
    event.stop_signal = "SIGILL"
    event.inferior_thread = SimpleNamespace(inferior=inferior)
    module.gdb.events.stop.emit(event)

    def execute(command, **kwargs):
        assert command == "signal SIGILL"
        exit_event(module, inferior, exit_code=0)

    module.gdb.execute = execute
    outcome = connector.deliver_pending_guest_signal_once()

    assert outcome.state is ExecutionState.EXITED
    assert outcome.exit_status == 0
    assert outcome.termination_signal is None


def test_pending_guest_signal_handler_stop_is_not_fabricated_as_termination(backend):
    module, connector, inferior, _, _ = backend
    event = module.gdb.SignalEvent()
    event.stop_signal = "SIGILL"
    event.inferior_thread = SimpleNamespace(inferior=inferior)
    module.gdb.events.stop.emit(event)

    def execute(command, **kwargs):
        assert command == "signal SIGILL"
        handler_stop = module.gdb.SignalEvent()
        handler_stop.stop_signal = "SIGTRAP"
        handler_stop.inferior_thread = SimpleNamespace(inferior=inferior)
        module.gdb.events.stop.emit(handler_stop)

    module.gdb.execute = execute
    outcome = connector.deliver_pending_guest_signal_once()

    assert outcome.state is ExecutionState.STOPPED
    assert outcome.stop_signal == module.signal.SIGTRAP
    assert not outcome.terminal_known
    assert connector.terminal_reason().signal == "SIGILL"
    assert connector.terminal_reason().delivered


def test_exit_signal_requires_exit_event(backend):
    module, connector, inferior, _, values = backend
    values["_exitsignal"] = SignalValue(15)
    assert not connector.execution_outcome().terminal_known
    exit_event(module, inferior)
    assert connector.execution_outcome().termination_signal == 15
    assert connector.execution_outcome().exit_status is None


@pytest.mark.parametrize("value", [None, SignalValue(0), SignalValue(-1), SignalValue(15, 2)])
def test_invalid_exit_signal_remains_unknown(backend, value):
    module, connector, inferior, _, values = backend
    values["_exitsignal"] = value
    exit_event(module, inferior)
    assert not connector.execution_outcome().terminal_known


@pytest.mark.parametrize("status", [-1, 256, True, "0"])
def test_invalid_exit_status_remains_unknown(backend, status):
    module, connector, inferior, _, values = backend
    values["_exitsignal"] = SignalValue(15)
    exit_event(module, inferior, exit_code=status)
    assert not connector.execution_outcome().terminal_known


@pytest.mark.parametrize("failure", ["invalid", "threads", "disconnect", "eof"])
def test_transport_loss_is_not_exit(backend, failure):
    module, connector, inferior, frame, _ = backend
    frame.read_register = lambda name: pytest.fail("unavailable register read")
    if failure == "invalid":
        inferior.is_valid = lambda: False
    elif failure == "threads":
        inferior.threads = lambda: []
    else:
        def failed():
            raise module.gdb.error(failure)
        inferior.threads = failed
    assert connector.execution_outcome().state is ExecutionState.UNKNOWN
    assert not connector.is_exited()
    with pytest.raises(RuntimeError, match="unknown"):
        connector.current_state()


def test_wrong_or_unidentified_inferior_exit_is_ignored(backend):
    module, connector, _, _, _ = backend
    exit_event(module, object(), exit_code=0)
    module.gdb.events.exited.emit(SimpleNamespace(exit_code=0))
    assert not connector.is_exited()


def test_wrong_inferior_signal_stop_is_ignored(backend):
    module, connector, _, frame, _ = backend
    frame.read_register = lambda name: pytest.fail("wrong-inferior register read")
    event = module.gdb.SignalEvent()
    event.stop_signal = "SIGTERM"
    event.inferior_thread = SimpleNamespace(inferior=object())
    module.gdb.events.stop.emit(event)
    assert connector.terminal_reason() is None
    assert connector.execution_outcome().stop_signal is None


def test_exit_signal_is_not_borrowed_from_selected_inferior(backend):
    module, connector, inferior, _, values = backend
    module.gdb.selected_inferior = lambda: object()
    values["_exitsignal"] = SignalValue(15)
    exit_event(module, inferior)
    assert not connector.execution_outcome().terminal_known


def test_exit_during_step_does_not_read_post_exit_pc(backend):
    module, connector, inferior, frame, values = backend
    values["_exitsignal"] = SignalValue(15)
    def execute(command, **kwargs):
        assert command == "si"
        assert values["_exitsignal"] is None
        frame.read_register = lambda name: pytest.fail("post-exit register read")
        exit_event(module, inferior, exit_code=0)
    module.gdb.execute = execute
    with pytest.raises(StopIteration):
        connector._step()
    assert connector.execution_outcome().exit_status == 0


def test_exit_during_run_until_does_not_fabricate_destination(backend):
    module, connector, inferior, frame, _ = backend
    iterator = object.__new__(module.GDBServerStateIterator)
    iterator.__dict__.update(connector.__dict__)
    deleted = []
    module.gdb.Breakpoint = lambda spec: SimpleNamespace(delete=lambda: deleted.append(spec))
    def execute(command, **kwargs):
        assert command == "continue"
        frame.read_register = lambda name: pytest.fail("post-exit register read")
        iterator._record_exit_event(SimpleNamespace(inferior=inferior, exit_code=7))
    module.gdb.execute = execute
    with pytest.raises(StopIteration):
        iterator._run_until_any([0x1001])
    assert iterator.execution_outcome().exit_status == 7
    assert deleted == ["*0x1001"]


def test_bounded_cutpoint_remains_stopped_not_exited(backend):
    module, connector, _, _, _ = backend
    iterator = object.__new__(module.GDBServerStateIterator)
    iterator.__dict__.update(connector.__dict__)
    module.gdb.Breakpoint = lambda spec: SimpleNamespace(delete=lambda: None)
    state = iterator._run_until_any([0x1000])
    assert isinstance(state, module.GDBProgramState)
    assert iterator.execution_outcome().state is ExecutionState.STOPPED
    assert not iterator.execution_outcome().terminal_known


@pytest.mark.parametrize("operation", ["register", "memory"])
def test_retained_lazy_state_cannot_read_backend_after_exit(backend, operation):
    module, connector, inferior, frame, _ = backend
    state = connector.current_state()
    frame.read_register = lambda name: pytest.fail("post-exit register read")
    inferior.read_memory = lambda *args: pytest.fail("post-exit memory read")
    exit_event(module, inferior, exit_code=0)
    with pytest.raises(RuntimeError, match="exited"):
        if operation == "register":
            state.read_register("RAX")
        else:
            state.read_memory(0x1000, 1)


@pytest.mark.parametrize("eof", [True, False])
def test_resume_transport_failure_overrides_stale_thread_state(backend, eof):
    module, connector, _, _, _ = backend
    def execute(*args, **kwargs):
        raise EOFError("EOF") if eof else module.gdb.error("Disconnected")
    module.gdb.execute = execute
    with pytest.raises((EOFError, module.gdb.error)):
        connector._step()
    assert connector.execution_outcome().state is ExecutionState.UNKNOWN
    assert not connector.is_exited()
    with pytest.raises(RuntimeError, match="unknown"):
        connector.current_state()


def test_foreign_exit_signal_cannot_leak_into_owned_exit(backend):
    module, connector, inferior, _, values = backend
    values["_exitsignal"] = SignalValue(15)
    exit_event(module, object())
    exit_event(module, inferior)
    assert not connector.execution_outcome().terminal_known


def test_wrong_selected_inferior_cannot_supply_state(backend):
    module, connector, _, frame, _ = backend
    module.gdb.selected_inferior = lambda: object()
    frame.read_register = lambda name: pytest.fail("wrong-inferior register read")
    with pytest.raises(RuntimeError, match="different GDB inferior"):
        connector.current_state()


def test_running_process_is_not_readable_or_terminal(backend):
    _, connector, inferior, frame, _ = backend
    inferior.threads = lambda: [SimpleNamespace(is_running=lambda: True)]
    frame.read_register = lambda name: pytest.fail("running register read")
    assert connector.execution_outcome().state is ExecutionState.RUNNING
    assert not connector.is_exited()
    with pytest.raises(RuntimeError, match="running"):
        connector.current_state()


def test_close_unsubscribes_without_claiming_exit(backend):
    module, connector, _, _, _ = backend
    connector.close()
    connector.close()
    assert module.gdb.events.stop.handlers == []
    assert module.gdb.events.exited.handlers == []
    assert not connector.is_exited()
