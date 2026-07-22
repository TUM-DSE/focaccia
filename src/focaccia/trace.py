from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Generic, TypeVar, overload

from .arch.arch import ArchitectureKey
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
    ):
        self.env = env
        self.addresses = tuple(addresses) if addresses is not None else None
        self._iterator = items
        self._position = 0
        self._exhausted = False

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
        if self._exhausted:
            raise StopIteration
        try:
            item = next(self._iterator)
        except StopIteration:
            self._exhausted = True
            raise
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
    ):
        self.env = env
        self._items = tuple(items)
        self.addresses = tuple(addresses) if addresses is not None else None
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
        return TransformStream(iter(self._items), self.env, self.addresses)

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
    ):
        self.env = env
        self.states = tuple(states)
        self.transforms = tuple(transforms)
        if len(self.states) != len(self.transforms) + 1:
            raise ValueError(
                "A transition trace requires exactly one more state boundary than "
                f"transforms: {len(self.states)} != {len(self.transforms)} + 1."
            )

    def __len__(self) -> int:
        return len(self.transforms)

    def _at(self, index: int) -> Transition[StateT_co, TransformT_co]:
        if index < 0:
            index += len(self)
        if index < 0 or index >= len(self):
            raise IndexError("transition trace index out of range")
        return Transition(self.states[index], self.transforms[index], self.states[index + 1])

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
        return f"Transition trace with {len(self)} transforms and {len(self.states)} states."
