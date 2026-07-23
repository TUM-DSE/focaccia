"""Quarantined native/QEMU thread-scheduler prototype.

This module preserves the pre-Step-10 scheduler implementation for possible
future redesign. It is deliberately disconnected from every production entry
point and requires the ``experimental-scheduler`` optional dependency. The
prototype is not supported, tested as a scheduler, or authorized for execution
by the normal Focaccia flake workflows.

Concurrency remains outside the implemented Veritas model. Importing this
module must never be necessary for ordinary tracing or validation.
"""

from __future__ import annotations

import logging
import os
import select
import socket
from typing import Any

import ptrace.debugger
from ptrace.debugger import (
    NewProcessEvent,
    ProcessEvent,
    ProcessExecution,
    ProcessExit,
    ProcessSignal,
    PtraceProcess,
)

from focaccia.deterministic import Event, SyscallEvent
from focaccia.snapshot import ReadableProgramState


logger = logging.getLogger("focaccia-experimental-scheduler")

SCHEDULER_SOCKET_PATH = "/tmp/memcached_scheduler.sock"

# If the scheduler does not provide input within this time, continue running
# the last chosen thread. This value is preserved from the prototype.
SCHED_TIMEOUT = 0


class ExperimentalSchedulerDisabledError(RuntimeError):
    """Raised when the quarantined prototype is invoked as an entry point."""


class PtraceSchedulerPrototype:
    """Preserved ptrace scheduler server; not used by production code."""

    def __init__(self, scheduler_socket_path: str = SCHEDULER_SOCKET_PATH):
        self.debugger = ptrace.debugger.PtraceDebugger()
        self.debugger.traceClone()
        self.debugger.traceFork()
        self.debugger.traceExec()

        if os.path.exists(scheduler_socket_path):
            os.unlink(scheduler_socket_path)

        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(scheduler_socket_path)
        self.server.listen(1)

        logger.info("Waiting for experimental scheduler at %s.", scheduler_socket_path)
        self.connection, _ = self.server.accept()
        logger.info("Experimental scheduler connected.")

    def _next(
        self,
        processes: dict[int, PtraceProcess],
        current_process: PtraceProcess | None,
    ) -> PtraceProcess | None:
        timeout = SCHED_TIMEOUT if SCHED_TIMEOUT > 0 else 0
        readable, _, _ = select.select([self.connection], [], [], timeout)
        if not readable:
            return current_process

        data = self.connection.recv(8)
        if not data:
            return current_process

        tid = int.from_bytes(data, byteorder="little", signed=False)
        process = processes.get(tid)
        if process is not None:
            logger.debug("Experimental scheduler selected TID %d.", tid)
            return process

        logger.debug("Experimental scheduler ignored inactive TID %d.", tid)
        return current_process

    @staticmethod
    def _handle_signal(event: ProcessSignal) -> None:
        process: PtraceProcess = event.process
        process.syscall(event.signum)

    def _handle_clone(self, event: NewProcessEvent) -> None:
        child = event.process
        parent = child.parent
        child_tid = child.pid
        logger.debug("New traced thread %d (parent %d).", child_tid, parent.pid)

        try:
            child.syscall()
        except Exception as error:
            logger.error("Error arming child %d: %s.", child_tid, error)
            try:
                self.debugger.deleteProcess(child)
            except Exception:
                pass

        try:
            parent.syscall()
        except Exception as error:
            logger.error("Error arming parent %d: %s.", parent.pid, error)
            try:
                self.debugger.deleteProcess(parent)
            except Exception:
                pass

    def _handle_exit(self, event: ProcessExit) -> None:
        dead_process: PtraceProcess = event.process
        logger.debug(
            "TID %d exited with status %s.",
            dead_process.pid,
            event.exitcode,
        )
        dead_process.detach()
        self.debugger.deleteProcess(dead_process)

    def _handle_syscall(self, event: ProcessExecution) -> None:
        try:
            instruction_pointer = event.process.getInstrPointer()
            logger.debug(
                "TID %d stopped at syscall PC %s.",
                self.current_process.pid,
                hex(instruction_pointer),
            )
        except Exception as error:
            logger.error(
                "Error reading PC for TID %d: %s.",
                self.current_process.pid,
                error,
            )

        self.current_process = self._next(self.debugger.dict, event.process)
        if (
            self.current_process is None
            or self.current_process not in self.debugger.list
        ):
            if self.is_exited():
                return
            self.current_process = self.debugger.list[0]
        self.current_process.syscall()

    def is_exited(self) -> bool:
        return len(self.debugger.list) == 0

    def schedule(self, pid: int) -> None:
        """Run the preserved prototype; no supported workflow calls this."""
        self.current_process = self.debugger.addProcess(pid, False)
        self.current_process.syscall()

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

    def close(self) -> None:
        self.connection.close()
        self.server.close()
        self.debugger.quit()


class GDBSchedulerPrototypeMixin:
    """Preserved client/context bookkeeping formerly mixed into QEMU replay.

    The host methods and fields intentionally mirror the old
    ``GDBServerStateIterator`` implementation. No production class inherits
    this mixin.
    """

    _process: Any
    _events: Any
    _scheduler_socket: socket.socket | None
    _thread_count: int
    _current_event_id: int
    _thread_map: dict[int, tuple[int, int]]
    _thread_context: dict[int, Event]

    def initialize_scheduler_prototype(self, event: Event) -> None:
        scheduler_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        scheduler_socket.connect(SCHEDULER_SOCKET_PATH)
        self._scheduler_socket = scheduler_socket
        self._thread_count = 1
        self._current_event_id = event.tid
        self._thread_map = {
            self._current_event_id: (self.current_tid(), self._thread_count)
        }
        self._thread_context = {}

    def current_tid(self) -> int:
        return self._process.threads()[0].ptid[1]

    def record_created_thread(self, event_tid: int, emulated_tid: int) -> None:
        self._thread_count += 1
        self._thread_map[event_tid] = (emulated_tid, self._thread_count)

    def handle_context_switch_prototype(
        self,
        event: SyscallEvent,
        post_event: SyscallEvent,
    ) -> ReadableProgramState | None:
        self._thread_context[self._current_event_id] = event
        self._current_event_id = post_event.tid
        tid, _ = self._thread_map[self._current_event_id]
        self.context_switch(tid)
        state = self.current_state()
        logger.debug(
            "Experimental scheduler selected %s for native event thread %s.",
            hex(tid),
            hex(post_event.tid),
        )

        if self._current_event_id in self._thread_context:
            self._thread_context.pop(self._current_event_id)
            return None
        if post_event.pc == state.read_pc():
            paired = self._events.match_pair(post_event)
            if paired is None:
                return None
            return state

        self._events.unmatch()
        self._step()
        return self.current_state()

    def context_switch(self, thread_number: int) -> None:
        if self._scheduler_socket is None:
            raise ExperimentalSchedulerDisabledError(
                "The experimental scheduler client is not connected."
            )
        data = thread_number.to_bytes(8, byteorder="little", signed=False)
        self._scheduler_socket.sendall(data)

    def close_scheduler_prototype(self) -> None:
        if self._scheduler_socket is not None:
            self._scheduler_socket.close()
            self._scheduler_socket = None


def main() -> None:
    raise ExperimentalSchedulerDisabledError(
        "The scheduler prototype is quarantined and has no supported entry point."
    )


if __name__ == "__main__":
    main()
