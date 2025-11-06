from __future__ import annotations
from typing import Generic, TypeVar

from .utils import file_hash

T = TypeVar('T')

class TraceEnvironment:
    """Data that defines the environment in which a trace was recorded."""
    def __init__(self,
                 binary: str,
                 argv: list[str],
                 envp: list[str],
                 binary_hash: str | None = None,
                 nondeterminism_log = None,
                 start_address: int | None = None,
                 stop_address:  int | None = None):
        self.argv = argv
        self.envp = envp
        self.binary_name = binary
        self.detlog = nondeterminism_log
        self.start_address = start_address
        self.stop_address = stop_address
        if binary_hash is None and self.binary_name is not None:
            self.binary_hash = file_hash(binary)
        else:
            self.binary_hash = binary_hash

    @classmethod
    def from_json(cls, json: dict) -> TraceEnvironment:
        """Parse a JSON object into a TraceEnvironment."""
        return cls(
            json['binary_name'],
            json['argv'],
            json['envp'],
            json['binary_hash'],
            None,
            json['start_address'],
            json['stop_address']
        )

    def to_json(self) -> dict:
        """Serialize a TraceEnvironment to a JSON object."""
        return {
            'binary_name': self.binary_name,
            'binary_hash': self.binary_hash,
            'argv': self.argv,
            'envp': self.envp,
            'start_address': self.start_address,
            'stop_address': self.stop_address
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TraceEnvironment):
            return False

        return self.binary_name == other.binary_name \
            and self.binary_hash == other.binary_hash \
            and self.argv == other.argv \
            and self.envp == other.envp

    def __repr__(self) -> str:
        return f'{self.binary_name} {" ".join(self.argv)}' \
               f'\n   bin-hash={self.binary_hash}' \
               f'\n   envp={repr(self.envp)}' \
               f'\n   start_address={self.start_address}' \
               f'\n   stop_address={self.stop_address}'

class Trace(Generic[T]):
    def __init__(self,
                 trace_states: list[T],
                 env: TraceEnvironment):
        self.env = env
        self.states = trace_states

    def __len__(self) -> int:
        return len(self.states)

    def __getitem__(self, i: int) -> T:
        return self.states[i]

    def __iter__(self):
        return iter(self.states)

    def __repr__(self) -> str:
        return f'Trace with {len(self.states)} trace points.' \
               f' Environment: {repr(self.env)}'

