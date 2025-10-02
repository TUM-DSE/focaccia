from __future__ import annotations
from typing import Generic, TypeVar

from .utils import file_hash

T = TypeVar('T')

class TraceEnvironment:
    """Data that defines the environment in which a trace was recorded."""
    def __init__(self,
                 binary: str,
                 argv: list[str],
                 cross_validate: bool,
                 envp: list[str],
                 binary_hash: str | None = None):
        self.argv = argv
        self.envp = envp
        self.binary_name = binary
        self.cross_validate = cross_validate
        if binary_hash is None:
            self.binary_hash = file_hash(binary)
        else:
            self.binary_hash = binary_hash

    @classmethod
    def from_json(cls, json: dict) -> TraceEnvironment:
        """Parse a JSON object into a TraceEnvironment."""
        return cls(
            json['binary_name'],
            json['argv'],
            json['cross_validate'],
            json['envp'],
            json['binary_hash'],
        )

    def to_json(self) -> dict:
        """Serialize a TraceEnvironment to a JSON object."""
        return {
            'binary_name': self.binary_name,
            'binary_hash': self.binary_hash,
            'argv': self.argv,
            'cross_validate': self.cross_validate,
            'envp': self.envp,
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TraceEnvironment):
            return False

        return self.binary_name == other.binary_name \
            and self.binary_hash == other.binary_hash \
            and self.argv == other.argv \
            and self.cross_validate == other.cross_validate \
            and self.envp == other.envp

    def __repr__(self) -> str:
        return f'{self.binary_name} {" ".join(self.argv)}' \
               f'\n   bin-hash={self.binary_hash}' \
               f'\n   options=cross-validate' \
               f'\n   envp={repr(self.envp)}'

class Trace(Generic[T]):
    def __init__(self,
                 trace_states: list[T],
                 env: TraceEnvironment):
        self.states = trace_states
        self.env = env

    def __len__(self) -> int:
        return len(self.states)

    def __getitem__(self, i: int) -> T:
        return self.states[i]

    def __iter__(self):
        return iter(self.states)

    def __repr__(self) -> str:
        return f'Trace with {len(self.states)} trace points.' \
               f' Environment: {repr(self.env)}'

