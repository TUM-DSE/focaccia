"""Small, pure Linux action contracts; not a syscall executor or replay engine.

Instantiate from each execution's own pre-call state, then check its observed
outcome. Never substitute native outputs into the emulator. These contracts do
not authorize removing symbolic exception markers: integration must retain the
action, validate instruction/control-flow semantics, and account for unchanged
state as well. Missing observations are unsupported, not successful validation.

Scope: single-thread Linux LP64 exit/exit_group, x86-64 ARCH_SET_FS, and
x86-64/AArch64 little-endian set_tid_address with an independently established
per-execution TID. AArch64 TPIDR_EL0 writes are ordinary MSR instructions, not
SET_FS actions; syscall validation checks that TPIDR_EL0 is preserved.
Startup memory mappings, randomness, signals and all other calls remain
unsupported. Entry/input compatibility is a separate obligation.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import struct
from collections.abc import Callable, Sequence
from typing import TypeAlias

from focaccia.arch.arch import ArchitectureKey
from focaccia.snapshot import ProgramState, ReadableProgramState


class UnsupportedNoReplayAction(ValueError):
    """The action or a required observation has no supported contract."""


class NoReplayActionMismatch(ValueError):
    """An independently observed effect violates its pre-call contract."""


class ExitScope(Enum):
    THREAD = "thread"
    GROUP = "group"


class NoReplayActionKind(Enum):
    EXIT = "exit"
    EXIT_GROUP = "exit_group"
    SET_FS = "arch_prctl_set_fs"
    SET_TID_ADDRESS = "set_tid_address"
    MMAP_ANONYMOUS_PRIVATE = "mmap_anonymous_private"
    MPROTECT_NONE_PAGE = "mprotect_none_page"


@dataclass(frozen=True, slots=True)
class NoReplayActionDescriptor:
    """Output-free policy identity for one ordered action boundary.

    No argument pointer, return value, TID or TLS base belongs here. A trace must
    retain occurrence order (including repeated PCs), and must never compose
    this boundary away. Persistence and backend execution are separate layers.
    Descriptor equality establishes policy identity, NOT equality of the fully
    instantiated effect labels required by the paper's same-action criterion.
    """

    architecture: ArchitectureKey
    pc: int
    kind: NoReplayActionKind

    def __post_init__(self) -> None:
        _uint(self.pc, 64, "action PC")
        if self.architecture not in (
            ArchitectureKey("x86_64", "little"),
            ArchitectureKey("aarch64", "little"),
            ArchitectureKey("aarch64", "big"),
        ):
            raise UnsupportedNoReplayAction("Unsupported action descriptor architecture.")
        if not isinstance(self.kind, NoReplayActionKind):
            raise ValueError("An action descriptor requires a typed policy kind.")
        if self.kind is NoReplayActionKind.SET_FS and self.architecture.isa != "x86_64":
            raise UnsupportedNoReplayAction("ARCH_SET_FS is x86-64-specific.")


def require_exit_only_entry(
    binary: str | None, binary_hash: str | None, pc: int, architecture: ArchitectureKey
) -> None:
    """Bind the no-replay slice to a hash-checked static Linux ELF entry.

    No interpreter or relocated entry may hide pre-trace kernel registrations.
    This is not a general libc/initial-stack compatibility contract.
    """
    from focaccia.utils import file_hash

    if binary is None or binary_hash is None:
        raise UnsupportedNoReplayAction("Exit-only capture requires a bound executable hash.")
    data = Path(binary).read_bytes()
    machine = {ArchitectureKey("x86_64", "little"): 62,
               ArchitectureKey("aarch64", "little"): 183}.get(architecture)
    if (
        machine is None
        or len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01"
        or struct.unpack_from("<HH", data, 16) != (2, machine)
        or struct.unpack_from("<Q", data, 24)[0] != pc
        or file_hash(binary) != binary_hash
    ):
        raise UnsupportedNoReplayAction("No-replay tracing requires the bound static x86-64 or AArch64 little-endian ELF entry.")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phcount = struct.unpack_from("<HH", data, 54)
    if phsize != 56 or phcount == 0 or phoff + phsize * phcount > len(data):
        raise UnsupportedNoReplayAction("Invalid ELF program-header table.")
    if any(struct.unpack_from("<I", data, phoff + i * phsize)[0] == 3 for i in range(phcount)):
        raise UnsupportedNoReplayAction("Exit-only tracing prohibits an ELF interpreter.")


def _uint(value: int, bits: int, name: str) -> None:
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must be an unsigned {bits}-bit integer.")


@dataclass(frozen=True, slots=True)
class ExitAction:
    """Linux truncates the int argument to its low eight bits for wait status.

    Retain the full argument and syscall scope so a matching status alone cannot
    hide a different invocation. No fabricated post-exit register state exists.
    Exit-time kernel cleanup (e.g. clear_child_tid) is not modeled here.
    """

    argument: int
    scope: ExitScope

    def __post_init__(self) -> None:
        _uint(self.argument, 64, "exit argument")
        if not isinstance(self.scope, ExitScope):
            raise ValueError("Exit scope must be explicit.")

    @property
    def status(self) -> int:
        return self.argument & 0xFF

    def validate_status(self, observed_status: int | None) -> None:
        """Caller must first prove a normal process exit, not a stop or signal.

        The argument is a decoded exit code, never an encoded waitpid status.
        This only validates the status effect; it does not classify termination.
        """
        if observed_status is None:
            raise UnsupportedNoReplayAction("Normal exit status is unavailable.")
        _uint(observed_status, 8, "observed exit status")
        if observed_status != self.status:
            raise NoReplayActionMismatch(
                f"Expected exit status {self.status}, observed {observed_status}."
            )


@dataclass(frozen=True, slots=True)
class SetFsAction:
    """Successful Linux x86-64 ARCH_SET_FS: RAX=0, FS.base=local RSI.

    Restrict to the common 47-bit user range (excluding the top guard page),
    rather than assume LA57 or a host-selected TASK_SIZE. The FS selector and
    RCX/R11 syscall clobbers are deliberately NOT specified by this effect
    contract. A backend must preserve those as explicit observation/semantics
    obligations; matching RAX and FS.base alone is not full state validation.
    There are no userspace memory writes or mappings in this action.
    """

    base: int

    def __post_init__(self) -> None:
        _uint(self.base, 64, "FS base")
        if self.base >= (1 << 47) - 4096:
            raise UnsupportedNoReplayAction("FS base exceeds the supported user range.")

    @property
    def unresolved_register_effects(self) -> tuple[str, ...]:
        return ("RCX", "R11", "FS")

    def validate_outputs(self, return_value: int | None, fs_base: int | None) -> None:
        if return_value is None or fs_base is None:
            raise UnsupportedNoReplayAction("ARCH_SET_FS requires return and FS-base observations.")
        _uint(return_value, 64, "syscall return")
        _uint(fs_base, 64, "observed FS base")
        if return_value != 0 or fs_base != self.base:
            raise NoReplayActionMismatch(
                f"Expected ARCH_SET_FS result (0, {self.base:#x}), "
                f"observed ({return_value:#x}, {fs_base:#x})."
            )


@dataclass(frozen=True, slots=True)
class ClearChildTidRegistration:
    """Predicted kernel registration, NOT proof of an observed memory write.

    Linux set_tid_address installs this pointer without dereferencing it. Exit
    cleanup must separately model the conditional zero write and futex wake;
    a successful return alone cannot discharge this effect obligation.
    """

    address: int

    def __post_init__(self) -> None:
        _uint(self.address, 64, "clear-child-tid address")


@dataclass(frozen=True, slots=True)
class SetTidAddressAction:
    """Per-execution TID return predicate plus a separate registration effect.

    expected_tid must come from independent execution context, not this syscall's
    return, a native recording, or a synthetic GDB thread identifier. Validating
    the return does not validate registration or its later exit-time effects.
    These are LOCAL contracts only: different returned TIDs are different action
    values under the paper's same-action criterion, just as different TIME(v)
    results are. Two locally valid calls with different TIDs do not establish
    native/emulator action equivalence; a justified relation remains required.
    """

    registration: ClearChildTidRegistration
    expected_tid: int

    def __post_init__(self) -> None:
        if not isinstance(self.registration, ClearChildTidRegistration):
            raise ValueError("A typed clear-child-tid registration is required.")
        _uint(self.expected_tid, 31, "execution-context TID")
        if self.expected_tid == 0:
            raise ValueError("Execution-context TID must be positive.")

    def validate_return(self, observed_return: int | None) -> None:
        if observed_return is None:
            raise UnsupportedNoReplayAction("set_tid_address return is unavailable.")
        _uint(observed_return, 64, "set_tid_address return")
        if observed_return != self.expected_tid:
            raise NoReplayActionMismatch(
                f"Expected execution-context TID {self.expected_tid}, observed {observed_return}."
            )


@dataclass(frozen=True, slots=True)
class AnonymousMmapAction:
    """A local fresh anonymous RW mapping, related by allocation occurrence.

    The returned address is deliberately absent: native and emulator allocate
    independently.  Only the requested length and fixed Linux ABI arguments
    are part of the same-action label.  Backends must bind the ordered
    occurrence to their own observed base before evaluating later addresses.
    """

    length: int

    def __post_init__(self) -> None:
        _uint(self.length, 64, "mmap length")
        if self.length == 0 or self.length > (1 << 47) - 4096:
            raise UnsupportedNoReplayAction("Anonymous mmap length is unsupported.")

    @property
    def mapped_length(self) -> int:
        return (self.length + 4095) & ~4095

    def validate_observed_result(
        self, return_value: int | None, read_memory: Callable[[int, int], bytes]
    ) -> int:
        """Validate success, alignment and the kernel-guaranteed zero-fill effect."""
        if return_value is None:
            raise UnsupportedNoReplayAction("Anonymous mmap return is unavailable.")
        _uint(return_value, 64, "mmap return")
        end = return_value + self.mapped_length
        if return_value % 4096 or end >= 1 << 64:
            raise NoReplayActionMismatch("Anonymous mmap returned an invalid local range.")
        data = read_memory(return_value, self.mapped_length)
        if len(data) != self.mapped_length:
            raise UnsupportedNoReplayAction("Anonymous mmap contents are not fully observable.")
        if any(data):
            raise NoReplayActionMismatch("Fresh anonymous mmap is not zero initialized.")
        return return_value

    def validate_local_result(
        self,
        return_value: int | None,
        mappings_before: Sequence[tuple[int, int]],
        mappings_after: Sequence[tuple[int, int, str]],
        read_memory: Callable[[int, int], bytes],
    ) -> int:
        """Validate a fresh local base without importing an oracle address.

        Mapping tuples are independently observed half-open ranges.  The new
        range must be exactly private anonymous ``rw-p`` and zero initialized.
        """
        return_value = self.validate_observed_result(return_value, read_memory)
        end = return_value + self.mapped_length
        if any(start < end and return_value < stop for start, stop in mappings_before):
            raise NoReplayActionMismatch("Anonymous mmap did not allocate a fresh local range.")
        matches = [item for item in mappings_after if item == (return_value, end, "rw-p anonymous")]
        if len(matches) != 1:
            raise UnsupportedNoReplayAction(
                "Anonymous mmap requires an independently observed private anonymous RW mapping."
            )
        return return_value


@dataclass(frozen=True, slots=True)
class MprotectNoneAction:
    """Protect exactly one page relative to a local ordered allocation."""

    occurrence: int
    offset: int
    length: int

    def __post_init__(self) -> None:
        _uint(self.occurrence, 64, "allocation occurrence")
        _uint(self.offset, 64, "mprotect offset")
        _uint(self.length, 64, "mprotect length")
        if self.offset % 4096 or self.length != 4096:
            raise UnsupportedNoReplayAction("Only one aligned PROT_NONE page is supported.")

    def validate_return(self, value: int | None) -> None:
        if value is None:
            raise UnsupportedNoReplayAction("mprotect return is unavailable.")
        _uint(value, 64, "mprotect return")
        if value != 0:
            raise NoReplayActionMismatch(f"mprotect failed with {value:#x}.")


NoReplayAction: TypeAlias = (
    ExitAction | SetFsAction | SetTidAddressAction | AnonymousMmapAction | MprotectNoneAction
)


@dataclass(frozen=True, slots=True)
class NoReplayMmapBoundary:
    """Ordered allocation identity; ``base`` is intentionally not persisted."""

    transform_index: int
    descriptor: NoReplayActionDescriptor
    length: int
    occurrence: int

    def __post_init__(self) -> None:
        _uint(self.transform_index, 64, "action transform index")
        _uint(self.occurrence, 64, "mmap occurrence")
        if (not isinstance(self.descriptor, NoReplayActionDescriptor)
                or self.descriptor.kind is not NoReplayActionKind.MMAP_ANONYMOUS_PRIVATE
                or self.descriptor.architecture != ArchitectureKey("x86_64", "little")):
            raise ValueError("An mmap boundary requires its typed x86-64 descriptor.")
        AnonymousMmapAction(self.length)


@dataclass(frozen=True, slots=True)
class NoReplayMprotectBoundary:
    transform_index: int
    descriptor: NoReplayActionDescriptor
    occurrence: int
    offset: int
    length: int

    def __post_init__(self) -> None:
        _uint(self.transform_index, 64, "action transform index")
        if (not isinstance(self.descriptor, NoReplayActionDescriptor)
                or self.descriptor.kind is not NoReplayActionKind.MPROTECT_NONE_PAGE):
            raise ValueError("An mprotect boundary requires its typed descriptor.")
        MprotectNoneAction(self.occurrence, self.offset, self.length)


@dataclass(frozen=True, slots=True)
class NoReplaySetFsBoundary:
    """Ordered successful SET_FS effect, not a recorded return to inject."""

    transform_index: int
    descriptor: NoReplayActionDescriptor
    base: int

    def __post_init__(self) -> None:
        _uint(self.transform_index, 64, "action transform index")
        if not isinstance(self.descriptor, NoReplayActionDescriptor) or self.descriptor.kind is not NoReplayActionKind.SET_FS:
            raise ValueError("A SET_FS boundary requires its typed descriptor.")
        SetFsAction(self.base)


def require_same_no_replay_action(native: NoReplayAction, emulated: NoReplayAction) -> None:
    """Same observed local predicates do not imply the paper's same action.

    TID equality is necessary but insufficient: current backends cannot observe
    clear_child_tid registration or validate its conditional exit cleanup.
    Never return successful equivalence for that unobserved effect.
    """
    if native != emulated:
        raise UnsupportedNoReplayAction(
            f"Different independently instantiated action values: native={native!r}, emulator={emulated!r}; "
            "this is not evidence of a mistranslation under the same-action criterion."
        )
    if isinstance(native, SetTidAddressAction):
        raise UnsupportedNoReplayAction(
            "Identical TID returns still leave clear_child_tid registration and exit cleanup unobserved."
        )


@dataclass(frozen=True, slots=True)
class NoReplaySetTidBoundary:
    """Context-relative thread identity, with private static registration storage.

    expected_tid is independently read task context, never a recorded return to
    inject. The live backend must prove the private lifetime before construction.
    """

    transform_index: int
    descriptor: NoReplayActionDescriptor
    address: int
    expected_tid: int

    def __post_init__(self) -> None:
        _uint(self.transform_index, 64, "action transform index")
        if (not isinstance(self.descriptor, NoReplayActionDescriptor)
                or self.descriptor.kind is not NoReplayActionKind.SET_TID_ADDRESS
                or self.descriptor.architecture not in (
                    ArchitectureKey("x86_64", "little"), ArchitectureKey("aarch64", "little"))):
            raise ValueError("A TID boundary requires a supported SET_TID_ADDRESS descriptor.")
        SetTidAddressAction(ClearChildTidRegistration(self.address), self.expected_tid)


def require_private_tid_storage(
    binary: str | None, address: int,
    architecture: ArchitectureKey = ArchitectureKey("x86_64", "little"),
) -> None:
    """Restrict registration to a writable static ELF PT_LOAD's private bytes.

    Used ONLY after fresh static-entry validation and while an exhaustive syscall
    allowlist prohibits clone/fork/mmap/exec, IPC and external output. Linux and
    QEMU ELF loaders map these segments privately. With one guest task throughout,
    there is no shared-mm waiter/observer when this address space is destroyed;
    the registration expires then, irrespective of an unobservable final clear.
    This does not assert a kernel write happened, nor cover shared memory/threads.
    """
    _uint(address, 64, "clear-child-tid address")
    if binary is None:
        raise UnsupportedNoReplayAction("Private TID storage requires the bound executable.")
    data = Path(binary).read_bytes()
    machine = {ArchitectureKey("x86_64", "little"): 62,
               ArchitectureKey("aarch64", "little"): 183}.get(architecture)
    if machine is None or len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<HH", data, 16) != (2, machine):
        raise UnsupportedNoReplayAction("Private TID storage requires a matching static ELF.")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, count = struct.unpack_from("<HH", data, 54)
    if phsize != 56 or not count or phoff + phsize * count > len(data):
        raise UnsupportedNoReplayAction("Invalid private-storage program headers.")
    headers = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize) for i in range(count)]
    if any(header[0] == 3 for header in headers):
        raise UnsupportedNoReplayAction("Private TID storage prohibits an interpreter.")
    if not any(kind == 1 and flags & 2 and start <= address and address + 4 <= start + size
               for kind, flags, _, start, _, _, size, _ in headers):
        raise UnsupportedNoReplayAction("clear_child_tid must lie in private writable static ELF storage.")


def no_replay_syscall_opcode(architecture: ArchitectureKey) -> bytes:
    """Exact supported instruction, not permission for other exception opcodes."""
    if architecture == ArchitectureKey("x86_64", "little"):
        return b"\x0f\x05"
    if architecture == ArchitectureKey("aarch64", "little"):
        return b"\x01\x00\x00\xd4"  # SVC #0; instructions are little endian.
    raise UnsupportedNoReplayAction(f"Unsupported no-replay instruction architecture: {architecture}.")


def snapshot_set_tid_inputs(state: ReadableProgramState) -> ProgramState:
    if state.arch.key == ArchitectureKey("aarch64", "little"):
        result = ProgramState(state.arch)
        for name in ("PC", "SP", "CPSR", "TPIDR", *[f"X{i}" for i in range(31)]):
            result.write_register(name, state.read_register(name))
        address = state.read_register("X0")
        result.write_memory(address, state.read_memory(address, 4))
        return result
    result = snapshot_set_fs_inputs(state)
    result.write_register("FS_BASE", state.read_register("FS_BASE"))
    address = state.read_register("RDI")
    result.write_memory(address, state.read_memory(address, 4))
    return result


def validate_set_tid_effect(
    before: ReadableProgramState, after: ReadableProgramState, expected_tid: int,
) -> SetTidAddressAction:
    """Validate the observable registration action and immediate successor."""
    action = prepare_no_replay_action(before, single_thread=True, expected_tid=expected_tid)
    if not isinstance(action, SetTidAddressAction):
        raise UnsupportedNoReplayAction("Expected SET_TID_ADDRESS action.")
    return_register = "X0" if before.arch.key.isa == "aarch64" else "RAX"
    instruction_size = 4 if before.arch.key.isa == "aarch64" else 2
    action.validate_return(after.read_register(return_register))
    address = action.registration.address
    if before.read_memory(address, 4) != after.read_memory(address, 4):
        raise NoReplayActionMismatch("SET_TID_ADDRESS unexpectedly changed registration storage.")
    if after.read_pc() != before.read_pc() + instruction_size:
        raise NoReplayActionMismatch("SET_TID_ADDRESS did not stop at its immediate successor.")
    return action


def validate_set_tid_transition(
    before: ReadableProgramState, after: ReadableProgramState, expected_tid: int,
    *, native_breakpoint_destination: bool = False,
) -> SetTidAddressAction:
    """Validate independently bound local return and complete supported GPR ABI.

    No userspace bytes are written by set_tid_address. Kernel registration is a
    lifetime effect discharged only by require_private_tid_storage plus the
    whole-program no-shared-mm allowlist, not by this return predicate.

    Native AArch64 run-until uses ptrace continue to a breakpoint, disabling
    single-step. Linux's user_regs_reset_single_step then clears PSTATE.SS
    (bit21). This explicit stop-mode contract predicts that ONE control bit;
    every other CPSR bit, including NZCV, SSBS, DIT and DAIF.D, must be unchanged.
    QEMU's ordinary single-step transaction does not opt into this contract.
    """
    if before.arch.key.isa == "x86_64":
        flags = before.read_register("RFLAGS")
        if before.read_register("FS") != 0 or flags & 0x10100:
            raise UnsupportedNoReplayAction(
                "SET_TID_ADDRESS requires zero FS selector and no TF/RF input flags."
            )
    action = validate_set_tid_effect(before, after, expected_tid)
    if before.arch.key == ArchitectureKey("aarch64", "little"):
        expected = {"PC": before.read_pc() + 4}
        for name in ("SP", "CPSR", "TPIDR", *[f"X{i}" for i in range(1, 31)]):
            expected[name] = before.read_register(name)
        if native_breakpoint_destination:
            # PSTATE.SS, not DIT (AArch64 DIT is bit24). Do not mask all flags
            # or debug bits: the resume operation specifically disables SS.
            expected['CPSR'] &= ~(1 << 21)
        for name, value in expected.items():
            observed = after.read_register(name)
            if observed != value:
                raise NoReplayActionMismatch(
                    f"SET_TID_ADDRESS violates independently predicted {name}={value:#x}; "
                    f"observed {observed:#x}."
                )
        return action
    flags = before.read_register("RFLAGS")
    expected = {"RIP": before.read_pc() + 2, "RCX": before.read_pc() + 2,
                "R11": flags, "RFLAGS": flags}
    for name in ("RBX", "RDX", "RDI", "RSI", "RBP", "RSP", "FS", "FS_BASE",
                 *[f"R{i}" for i in range(8, 11)], *[f"R{i}" for i in range(12, 16)]):
        expected[name] = before.read_register(name)
    for name, value in expected.items():
        if after.read_register(name) != value:
            raise NoReplayActionMismatch(f"SET_TID_ADDRESS violates independently predicted {name}={value:#x}.")
    return action


def snapshot_set_fs_inputs(state: ReadableProgramState) -> ProgramState:
    """Freeze pre-call inputs before either backend resumes its own execution."""
    result = ProgramState(state.arch)
    for name in ("RIP", "RAX", "RBX", "RCX", "RDX", "RDI", "RSI", "RBP", "RSP",
                 "RFLAGS", "FS", *[f"R{i}" for i in range(8, 16)]):
        result.write_register(name, state.read_register(name))
    if result.read_register("FS") != 0 or result.read_register("RFLAGS") & 0x10100:
        raise UnsupportedNoReplayAction("SET_FS requires zero FS selector and no TF/RF input flags.")
    return result


def validate_set_fs_effect(
    before: ReadableProgramState, after: ReadableProgramState
) -> SetFsAction:
    """Validate the observable kernel effect required before continuation.

    This deliberately does not validate ordinary architectural outputs.  A
    consumer may continue from the actual immediate successor after this core
    effect succeeds so its normal transform comparison can report RCX/R11 (or
    other register) mistranslations and validate the remaining execution.
    """
    action = prepare_no_replay_action(before, single_thread=True)
    if not isinstance(action, SetFsAction):
        raise UnsupportedNoReplayAction("Expected ARCH_SET_FS action.")
    action.validate_outputs(after.read_register("RAX"), after.read_register("FS_BASE"))
    if after.read_pc() != before.read_pc() + 2:
        raise NoReplayActionMismatch("SET_FS did not stop at its immediate successor.")
    return action


def validate_set_fs_transition(
    before: ReadableProgramState, after: ReadableProgramState
) -> SetFsAction:
    """Check the complete restricted Linux x86-64 SET_FS transaction.

    Native capture uses this strict check.  A diagnostic consumer may instead
    use :func:`validate_set_fs_effect` and expose architectural differences to
    the ordinary transform matcher without treating them as unknown effects.
    """
    action = validate_set_fs_effect(before, after)
    flags = before.read_register("RFLAGS")
    if before.read_register("FS") != 0 or flags & 0x10100:
        raise UnsupportedNoReplayAction("SET_FS requires zero FS selector and no TF/RF input flags.")
    expected = {"RIP": before.read_pc() + 2, "RCX": before.read_pc() + 2,
                "R11": flags, "RFLAGS": flags, "FS": 0}
    for name in ("RBX", "RDX", "RDI", "RSI", "RBP", "RSP", *[f"R{i}" for i in range(8, 11)], *[f"R{i}" for i in range(12, 16)]):
        expected[name] = before.read_register(name)
    for name, value in expected.items():
        if after.read_register(name) != value:
            raise NoReplayActionMismatch(f"SET_FS violates independently predicted {name}={value:#x}.")
    return action


def describe_no_replay_action(state: ReadableProgramState) -> NoReplayActionDescriptor:
    """Choose a descriptor from pre-call inputs only, without executing anything."""
    key = state.arch.key
    if key == ArchitectureKey("x86_64", "little"):
        number = state.read_register("RAX")
        kinds = {
            60: NoReplayActionKind.EXIT,
            231: NoReplayActionKind.EXIT_GROUP,
            218: NoReplayActionKind.SET_TID_ADDRESS,
            9: NoReplayActionKind.MMAP_ANONYMOUS_PRIVATE,
            10: NoReplayActionKind.MPROTECT_NONE_PAGE,
        }
        if number == 158 and state.read_register("RDI") == 0x1002:
            kinds[158] = NoReplayActionKind.SET_FS
        if number in (9, 10):
            # Descriptor recognition is policy recognition, not permission to
            # defer argument validation until after the kernel has executed.
            prepare_no_replay_action(state, single_thread=True)
    elif key in (ArchitectureKey("aarch64", "little"), ArchitectureKey("aarch64", "big")):
        number = state.read_register("X8")
        kinds = {
            93: NoReplayActionKind.EXIT,
            94: NoReplayActionKind.EXIT_GROUP,
            96: NoReplayActionKind.SET_TID_ADDRESS,
        }
    else:
        raise UnsupportedNoReplayAction(f"Unsupported no-replay architecture: {key}.")
    _uint(number, 64, "syscall number")
    if number not in kinds:
        raise UnsupportedNoReplayAction(f"Unsupported no-replay syscall/variant: {number}.")
    return NoReplayActionDescriptor(key, state.read_pc(), kinds[number])


def prepare_no_replay_action(
    state: ReadableProgramState,
    *,
    single_thread: bool,
    expected_tid: int | None = None,
    descriptor: NoReplayActionDescriptor | None = None,
) -> NoReplayAction:
    """Read only required ABI inputs; never advance or write the target.

    The caller must establish Linux LP64 and single-thread provenance. Raw
    exit-time clear_child_tid/robust-list effects require separate integration
    support. Unknown register reads propagate; no default zeros are used.
    """
    if single_thread is not True:
        raise UnsupportedNoReplayAction("No-replay actions require a proven single thread.")
    if descriptor is not None and describe_no_replay_action(state) != descriptor:
        raise NoReplayActionMismatch("Observed pre-call policy/PC differs from action descriptor.")
    key = state.arch.key
    if key == ArchitectureKey("x86_64", "little"):
        number_register, argument_register = "RAX", "RDI"
        exit_number, group_number = 60, 231
    elif key in (ArchitectureKey("aarch64", "little"), ArchitectureKey("aarch64", "big")):
        number_register, argument_register = "X8", "X0"
        exit_number, group_number = 93, 94
    else:
        raise UnsupportedNoReplayAction(f"Unsupported no-replay architecture: {key}.")
    number = state.read_register(number_register)
    _uint(number, 64, "syscall number")
    if number in (exit_number, group_number):
        return ExitAction(
            state.read_register(argument_register),
            ExitScope.THREAD if number == exit_number else ExitScope.GROUP,
        )
    tid_number = 218 if key.isa == "x86_64" else 96
    if key == ArchitectureKey("x86_64", "little") and number == 10:
        address = state.read_register("RDI")
        length = state.read_register("RSI")
        prot = state.read_register("RDX")
        if prot != 0:
            raise UnsupportedNoReplayAction("Only PROT_NONE mprotect is supported.")
        matches = [
            occurrence for occurrence, base in enumerate(state.allocation_bases)
            if address == base + 4096
        ]
        if len(matches) != 1:
            raise UnsupportedNoReplayAction(
                "mprotect address must be one page into one local ordered allocation."
            )
        return MprotectNoneAction(matches[0], 4096, length)
    if key == ArchitectureKey("x86_64", "little") and number == 9:
        address = state.read_register("RDI")
        length = state.read_register("RSI")
        prot = state.read_register("RDX")
        flags = state.read_register("R10")
        descriptor_fd = state.read_register("R8")
        offset = state.read_register("R9")
        if (address, prot, flags, descriptor_fd, offset) != (
            0, 3, 0x22, 0xFFFFFFFFFFFFFFFF, 0
        ):
            raise UnsupportedNoReplayAction(
                "Only mmap(NULL, length, PROT_READ|PROT_WRITE, "
                "MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) is supported."
            )
        return AnonymousMmapAction(length)
    if number == tid_number:
        if expected_tid is None:
            raise UnsupportedNoReplayAction(
                "set_tid_address requires an independent execution-context TID."
            )
        return SetTidAddressAction(
            ClearChildTidRegistration(state.read_register(argument_register)), expected_tid
        )
    if key == ArchitectureKey("x86_64", "little") and number == 158:
        operation = state.read_register("RDI")
        _uint(operation, 64, "arch_prctl operation")
        if operation == 0x1002:  # Linux UAPI ARCH_SET_FS; no GET/GS/CPUID variants.
            return SetFsAction(state.read_register("RSI"))
        raise UnsupportedNoReplayAction(f"Unsupported arch_prctl operation: {operation:#x}.")
    raise UnsupportedNoReplayAction(f"Unsupported no-replay syscall: {number} on {key}.")
