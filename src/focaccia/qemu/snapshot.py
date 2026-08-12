"""Backend-neutral planning and collection of minimal QEMU snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from miasm.expression.expression import ExprMem

from focaccia.arch import Arch
from focaccia.snapshot import (
    MemoryAccessError,
    ProgramState,
    ReadableProgramState,
    RegisterAccessError,
)
from focaccia.symbolic import (
    SymbolEvaluationError,
    SymbolicDependencies,
    SymbolicTraceItem,
    SymbolicTransform,
    eval_symbol,
)
from focaccia.trace import TraceDiagnostic


AddressState = Literal["previous", "current"]
SnapshotIssueKind = Literal[
    "register-unavailable",
    "memory-address-unavailable",
    "memory-unavailable",
]


class SnapshotPlanningError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MemoryDependency:
    expression: ExprMem
    address_state: AddressState


@dataclass(frozen=True, slots=True)
class SnapshotPlan:
    architecture: Arch
    registers: tuple[str, ...]
    memory: tuple[MemoryDependency, ...]


@dataclass(frozen=True, slots=True)
class SnapshotIssue:
    kind: SnapshotIssueKind
    message: str
    register: str | None = None
    address: int | None = None
    size: int | None = None


@dataclass(frozen=True, slots=True)
class SnapshotCollection:
    state: ProgramState
    issues: tuple[SnapshotIssue, ...]


def _transform_architecture(
    current_state: ReadableProgramState,
    incoming: SymbolicTraceItem | None,
    outgoing: SymbolicTraceItem | None,
) -> Arch:
    transforms = [item for item in (incoming, outgoing) if item is not None]
    architecture = transforms[0].arch if transforms else current_state.arch
    for transform in transforms[1:]:
        if transform.arch != architecture:
            raise SnapshotPlanningError(
                "Incoming and outgoing transforms use different architectures."
            )
    if current_state.arch != architecture:
        raise SnapshotPlanningError(
            f"Concrete architecture {current_state.arch} does not match "
            f"symbolic architecture {architecture}."
        )
    return architecture


def merge_snapshot_plans(*plans: SnapshotPlan) -> SnapshotPlan:
    """Merge candidate plans without weakening architecture identity."""
    if not plans:
        raise SnapshotPlanningError("Cannot merge an empty snapshot-plan set.")
    architecture = plans[0].architecture
    registers: set[str] = set()
    memory: list[MemoryDependency] = []
    seen_memory: set[tuple[ExprMem, AddressState]] = set()
    for plan in plans:
        if plan.architecture != architecture:
            raise SnapshotPlanningError("Candidate snapshot plans use different architectures.")
        registers.update(plan.registers)
        for dependency in plan.memory:
            key = (dependency.expression, dependency.address_state)
            if key not in seen_memory:
                seen_memory.add(key)
                memory.append(dependency)
    return SnapshotPlan(architecture, tuple(sorted(registers)), tuple(memory))


def plan_minimal_snapshot(
    current_state: ReadableProgramState,
    incoming: SymbolicTraceItem | None,
    outgoing: SymbolicTraceItem | None,
) -> SnapshotPlan:
    """Plan values needed to validate transforms on either side of a boundary."""
    architecture = _transform_architecture(current_state, incoming, outgoing)
    registers: set[str] = set()
    memory: list[MemoryDependency] = []

    if isinstance(incoming, SymbolicTransform):
        registers.update(incoming.validation_register_outputs())
        memory.extend(
            MemoryDependency(write.destination, "previous") for write in incoming.memory_writes
        )

    if isinstance(outgoing, SymbolicTransform):
        registers.update(outgoing.get_used_registers())
        memory.extend(
            MemoryDependency(expression, "current")
            for expression in outgoing.get_used_memory_addresses()
        )

    unique_memory: list[MemoryDependency] = []
    seen_memory: set[tuple[ExprMem, AddressState]] = set()
    for dependency in memory:
        key = (dependency.expression, dependency.address_state)
        if key in seen_memory:
            continue
        seen_memory.add(key)
        unique_memory.append(dependency)

    return SnapshotPlan(
        architecture,
        tuple(sorted(registers)),
        tuple(unique_memory),
    )


def plan_symbolic_dependencies(
    current_state: ReadableProgramState,
    dependencies: SymbolicDependencies,
) -> SnapshotPlan:
    """Convert a precomposed source-dependency union into a snapshot plan."""
    if current_state.arch != dependencies.arch:
        raise SnapshotPlanningError(
            f"Concrete architecture {current_state.arch} does not match "
            f"symbolic architecture {dependencies.arch}."
        )
    return SnapshotPlan(
        dependencies.arch,
        tuple(sorted(dependencies.registers)),
        tuple(MemoryDependency(expression, "current") for expression in dependencies.memory),
    )


def collect_snapshot_plan(
    previous_state: ReadableProgramState,
    current_state: ReadableProgramState,
    plan: SnapshotPlan,
) -> SnapshotCollection:
    """Collect a prepared plan, retaining unavailable values as unknowns."""
    if current_state.arch != plan.architecture:
        raise SnapshotPlanningError(
            f"Concrete architecture {current_state.arch} does not match "
            f"snapshot architecture {plan.architecture}."
        )
    if previous_state.arch != plan.architecture:
        raise SnapshotPlanningError(
            f"Previous concrete architecture {previous_state.arch} does not match "
            f"snapshot architecture {plan.architecture}."
        )

    snapshot = ProgramState(plan.architecture)
    snapshot.write_register("PC", current_state.read_pc())
    issues: list[SnapshotIssue] = []

    for register in plan.registers:
        try:
            value = current_state.read_register(register)
        except RegisterAccessError as error:
            issues.append(
                SnapshotIssue(
                    "register-unavailable",
                    f"Unable to observe register {register}: {error}.",
                    register=register,
                )
            )
            continue
        snapshot.write_register(register, value)

    for dependency in plan.memory:
        expression = dependency.expression
        if expression.size <= 0 or expression.size % 8 != 0:
            raise SnapshotPlanningError(f"Non-byte memory expression width {expression.size}.")
        address_state = previous_state if dependency.address_state == "previous" else current_state
        try:
            address = eval_symbol(expression.ptr, address_state)
        except (RegisterAccessError, MemoryAccessError, SymbolEvaluationError, ValueError) as error:
            issues.append(
                SnapshotIssue(
                    "memory-address-unavailable",
                    f"Unable to evaluate memory address {expression.ptr}: {error}.",
                    size=expression.size // 8,
                )
            )
            continue

        size = expression.size // 8
        try:
            data = current_state.read_memory(address, size)
        except MemoryAccessError as error:
            issues.append(
                SnapshotIssue(
                    "memory-unavailable",
                    f"Unable to observe {size} bytes at {hex(address)}: {error}.",
                    address=address,
                    size=size,
                )
            )
            continue
        if len(data) != size:
            issues.append(
                SnapshotIssue(
                    "memory-unavailable",
                    f"Concrete backend returned {len(data)} of {size} bytes at {hex(address)}.",
                    address=address,
                    size=size,
                )
            )
            continue
        snapshot.write_memory(address, data)

    return SnapshotCollection(snapshot, tuple(issues))


def collect_minimal_snapshot(
    previous_state: ReadableProgramState,
    current_state: ReadableProgramState,
    incoming: SymbolicTraceItem | None,
    outgoing: SymbolicTraceItem | None,
    *,
    source_outgoing: SymbolicTraceItem | None = None,
) -> SnapshotCollection:
    """Collect a plan, retaining unavailable values as explicit unknowns."""
    plan = plan_minimal_snapshot(
        current_state,
        incoming,
        source_outgoing if source_outgoing is not None else outgoing,
    )
    return collect_snapshot_plan(previous_state, current_state, plan)


def snapshot_diagnostics(
    collection: SnapshotCollection,
    concrete_index: int,
    transform_index: int | None,
) -> tuple[TraceDiagnostic, ...]:
    return tuple(
        TraceDiagnostic(
            "incomplete",
            f"snapshot-{issue.kind}",
            issue.message,
            concrete_index,
            transform_index,
        )
        for issue in collection.issues
    )
