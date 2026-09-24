from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Generic, Literal, TypeVar, overload

from .arch.arch import ArchitectureKey
from .completion import TraceCompletion, TraceScope, validate_trace_metadata
from .utils import file_hash

if TYPE_CHECKING:
    from .deterministic import DeterministicLog


class _MissingBinaryHash:
    pass


_MISSING_BINARY_HASH = _MissingBinaryHash()


@dataclass(frozen=True, slots=True, init=False)
class TraceEnvironment:
    """Immutable metadata describing how a trace was recorded."""

    binary_name: str | None
    argv: tuple[str, ...]
    envp: tuple[str, ...]
    binary_hash: str | None
    start_address: int | None
    stop_address: int | None
    replay_provenance: str | None
    architecture: ArchitectureKey | None
    detlog: DeterministicLog | None = field(compare=False, hash=False, repr=False)

    def __init__(
        self,
        binary: str | None,
        argv: Iterable[str],
        envp: Iterable[str],
        binary_hash: str | None | _MissingBinaryHash = _MISSING_BINARY_HASH,
        nondeterminism_log: DeterministicLog | None = None,
        start_address: int | None = None,
        stop_address: int | None = None,
        replay_provenance: str | None = None,
        architecture: ArchitectureKey | None = None,
    ):
        if isinstance(binary_hash, _MissingBinaryHash):
            binary_hash = file_hash(binary) if binary else None
        if replay_provenance is None and nondeterminism_log is not None:
            base_directory = nondeterminism_log.base_directory
            if base_directory:
                replay_provenance = str(base_directory)

        object.__setattr__(self, "binary_name", binary)
        object.__setattr__(self, "argv", tuple(argv))
        object.__setattr__(self, "envp", tuple(envp))
        object.__setattr__(self, "binary_hash", binary_hash)
        object.__setattr__(self, "start_address", start_address)
        object.__setattr__(self, "stop_address", stop_address)
        object.__setattr__(self, "replay_provenance", replay_provenance)
        object.__setattr__(self, "architecture", architecture)
        object.__setattr__(self, "detlog", nondeterminism_log)

    @classmethod
    def from_json(cls, document: dict) -> TraceEnvironment:
        """Parse the currently supported environment object."""
        architecture_document = document.get("architecture")
        architecture = None
        if architecture_document is not None:
            isa = architecture_document["isa"]
            endianness = architecture_document["endianness"]
            if endianness not in ("little", "big"):
                raise ValueError(f"Unsupported trace architecture endianness: {endianness}")
            architecture = ArchitectureKey(isa, endianness)

        return cls(
            document["binary_name"],
            document["argv"],
            document["envp"],
            document["binary_hash"],
            start_address=document.get("start_address"),
            stop_address=document.get("stop_address"),
            replay_provenance=document.get("replay_provenance"),
            architecture=architecture,
        )

    def to_json(self) -> dict:
        """Serialize trace metadata without the runtime replay-log object."""
        architecture = None
        if self.architecture is not None:
            architecture = {
                "isa": self.architecture.isa,
                "endianness": self.architecture.endianness,
            }
        return {
            "binary_name": self.binary_name,
            "binary_hash": self.binary_hash,
            "argv": list(self.argv),
            "envp": list(self.envp),
            "start_address": self.start_address,
            "stop_address": self.stop_address,
            "replay_provenance": self.replay_provenance,
            "architecture": architecture,
        }

    def with_architecture(self, architecture: ArchitectureKey) -> TraceEnvironment:
        """Return equivalent metadata with an explicit architecture identity."""
        if self.architecture == architecture:
            return self
        if self.architecture is not None:
            raise ValueError(
                f"Trace architecture {self.architecture} conflicts with {architecture}."
            )
        return TraceEnvironment(
            self.binary_name,
            self.argv,
            self.envp,
            self.binary_hash,
            nondeterminism_log=self.detlog,
            start_address=self.start_address,
            stop_address=self.stop_address,
            replay_provenance=self.replay_provenance,
            architecture=architecture,
        )

    def __repr__(self) -> str:
        return (
            f'{self.binary_name} {" ".join(self.argv)}'
            f"\n   bin-hash={self.binary_hash}"
            f"\n   envp={self.envp!r}"
            f"\n   start_address={self.start_address}"
            f"\n   stop_address={self.stop_address}"
            f"\n   replay_provenance={self.replay_provenance}"
            f"\n   architecture={self.architecture}"
        )


DiagnosticLevel = Literal["info", "incomplete", "error"]


@dataclass(frozen=True, slots=True)
class TraceDiagnostic:
    """Structured diagnostic produced while matching or validating a trace."""

    level: DiagnosticLevel
    code: str
    message: str
    concrete_index: int | None = None
    transform_index: int | None = None


T_co = TypeVar("T_co", covariant=True)


class StreamExhaustedError(EOFError):
    """Raised when an explicit stream skip extends beyond its input."""

    def __init__(self, requested: int, skipped: int, position: int):
        self.requested = requested
        self.skipped = skipped
        self.position = position
        super().__init__(
            f"Unable to skip {requested} trace items: exhausted after {skipped} "
            f"at cursor position {position}."
        )


class TransformStream(Iterator[T_co], Generic[T_co]):
    """A one-shot trace cursor with explicit skip and exhaustion behavior."""

    def __init__(
        self,
        items: Iterator[T_co],
        env: TraceEnvironment,
        addresses: Iterable[int] | None = None,
        *,
        scope: TraceScope = TraceScope.UNSPECIFIED,
        completion: TraceCompletion | None = None,
    ):
        self.env = env
        self.scope = scope
        validate_trace_metadata(scope, completion)
        self._completion = completion
        self.addresses = tuple(addresses) if addresses is not None else None
        self._iterator = items
        self._position = 0
        self._exhausted = False
        self._final_pc: int | None = None
        self._item_kind = "transforms"
        self._failure: Exception | None = None

    @property
    def completion(self) -> TraceCompletion | None:
        """Unconsumed or truncated streams cannot establish completion."""
        return self._completion if self.exhausted else None

    @property
    def declared_completion(self) -> TraceCompletion | None:
        """Return unverified header metadata needed to configure consumption.

        This declaration may authorize expected no-replay actions, but it is not
        completion evidence. ``completion`` remains unavailable until verified
        EOF and cardinality checks succeed.
        """
        return self._completion

    @property
    def position(self) -> int:
        return self._position

    @property
    def exhausted(self) -> bool:
        return self._exhausted

    def require_addresses(self) -> tuple[int, ...]:
        if self.addresses is None:
            raise ValueError("This transform stream has no address index.")
        return self.addresses

    def __iter__(self) -> TransformStream[T_co]:
        return self

    def __next__(self) -> T_co:
        if self._failure is not None:
            raise self._failure
        if self._exhausted:
            raise StopIteration
        try:
            item = next(self._iterator)
        except StopIteration:
            if self._completion is not None:
                self._completion.validate_binding(self._item_kind, self.position, self._final_pc)
            self._exhausted = True
            raise
        except Exception as error:
            # A malformed/truncated frame is permanently fatal for this cursor.
            self._failure = error
            raise
        if self._completion is not None:
            read_pc = getattr(item, "read_pc", None)
            self._item_kind = "states" if callable(read_pc) else "transforms"
            self._final_pc = read_pc() if callable(read_pc) else getattr(item, "range", (None, None))[1]
        self._position += 1
        return item

    def skip(self, count: int = 1) -> None:
        if count < 0:
            raise ValueError("Cannot skip a negative number of trace items.")

        skipped = 0
        while skipped < count:
            try:
                next(self)
            except StopIteration as error:
                raise StreamExhaustedError(count, skipped, self.position) from error
            skipped += 1


class MaterializedTrace(Sequence[T_co], Generic[T_co]):
    """A repeatable trace sequence with optional explicit addresses."""

    def __init__(
        self,
        items: Iterable[T_co],
        env: TraceEnvironment,
        addresses: Iterable[int] | None = None,
        *,
        scope: TraceScope = TraceScope.UNSPECIFIED,
        completion: TraceCompletion | None = None,
    ):
        self.env = env
        validate_trace_metadata(scope, completion)
        self.scope = scope
        self.completion = completion
        self.declared_completion = completion
        self._items = tuple(items)
        self.addresses = tuple(addresses) if addresses is not None else None
        if completion is not None:
            if self._items:
                final = self._items[-1]
                read_pc = getattr(final, "read_pc", None)
                if callable(read_pc):
                    completion.validate_binding("states", len(self), read_pc())
                else:
                    bounds = getattr(final, "range", (None, None))
                    completion.validate_binding("transforms", len(self), bounds[1])
            else:
                completion.validate_binding("transforms", 0, None)
        if self.addresses is not None and len(self.addresses) != len(self._items):
            raise ValueError(
                "Trace address count must equal item count: "
                f"{len(self.addresses)} != {len(self._items)}."
            )

    def require_addresses(self) -> tuple[int, ...]:
        if self.addresses is None:
            raise ValueError("This materialized trace has no address index.")
        return self.addresses

    def cursor(self) -> TransformStream[T_co]:
        """Create an independent one-shot cursor over this trace."""
        return TransformStream(
            iter(self._items), self.env, self.addresses,
            scope=self.scope, completion=self.completion,
        )

    def __len__(self) -> int:
        return len(self._items)

    @overload
    def __getitem__(self, index: int) -> T_co: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[T_co, ...]: ...

    def __getitem__(self, index: int | slice) -> T_co | tuple[T_co, ...]:
        return self._items[index]

    def __iter__(self) -> Iterator[T_co]:
        return iter(self._items)

    def __repr__(self) -> str:
        return f"Materialized trace with {len(self)} points. Environment: {self.env!r}"


StateT_co = TypeVar("StateT_co", covariant=True)
TransformT_co = TypeVar("TransformT_co", covariant=True)


@dataclass(frozen=True, slots=True)
class Transition(Generic[StateT_co, TransformT_co]):
    source: StateT_co
    transform: TransformT_co
    destination: StateT_co


class TransitionTrace(
    Sequence[Transition[StateT_co, TransformT_co]],
    Generic[StateT_co, TransformT_co],
):
    """Materialized state boundaries paired with their intervening transforms."""

    def __init__(
        self,
        states: Sequence[StateT_co],
        transforms: Sequence[TransformT_co],
        env: TraceEnvironment,
        *,
        scope: TraceScope = TraceScope.UNSPECIFIED,
        completion: TraceCompletion | None = None,
    ):
        self.env = env
        validate_trace_metadata(scope, completion)
        self.scope = scope
        self.completion = completion
        self.state_boundaries = tuple(states)
        self.transforms = tuple(transforms)
        if completion is not None:
            read_pc = getattr(self.state_boundaries[-1], "read_pc", None) if self.state_boundaries else None
            completion.validate_binding("states", len(self.state_boundaries), read_pc() if callable(read_pc) else None)
            if completion.transform_count != len(self.transforms):
                raise ValueError("Completion transform count differs from trace.")
        if len(self.state_boundaries) != len(self.transforms) + 1:
            raise ValueError(
                "A transition trace requires exactly one more state boundary than "
                f"transforms: {len(self.state_boundaries)} != "
                f"{len(self.transforms)} + 1."
            )

    def __len__(self) -> int:
        return len(self.transforms)

    def _at(self, index: int) -> Transition[StateT_co, TransformT_co]:
        if index < 0:
            index += len(self)
        if index < 0 or index >= len(self):
            raise IndexError("transition trace index out of range")
        return Transition(
            self.state_boundaries[index],
            self.transforms[index],
            self.state_boundaries[index + 1],
        )

    @overload
    def __getitem__(self, index: int) -> Transition[StateT_co, TransformT_co]: ...

    @overload
    def __getitem__(
        self, index: slice
    ) -> tuple[Transition[StateT_co, TransformT_co], ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> Transition[StateT_co, TransformT_co] | tuple[Transition[StateT_co, TransformT_co], ...]:
        if isinstance(index, slice):
            return tuple(self._at(i) for i in range(*index.indices(len(self))))
        return self._at(index)

    def __iter__(self) -> Iterator[Transition[StateT_co, TransformT_co]]:
        for index in range(len(self)):
            yield self._at(index)

    def __repr__(self) -> str:
        return (
            f"Transition trace with {len(self)} transforms and "
            f"{len(self.state_boundaries)} states."
        )
