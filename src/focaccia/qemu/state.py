"""Shared cached program-state boundary for QEMU observation backends."""

from __future__ import annotations

from dataclasses import dataclass

from focaccia.arch import Arch
from focaccia.snapshot import MemoryAccessError, ProgramState, RegisterAccessError


@dataclass(frozen=True, slots=True)
class RegisterObservation:
    """One backend register observation with an explicit logical width."""

    name: str
    value: int
    num_bits: int


class CachedBackendProgramState(ProgramState):
    """Cache backend observations without manufacturing unobserved state.

    Backends fetch a canonical base register where possible. A backend may
    return a narrower architectural alias (for example, EFLAGS for RFLAGS); in
    that case only the alias bits become valid and wider reads remain unknown.
    """

    def __init__(self, arch: Arch):
        super().__init__(arch)
        self._observed_register_bases: set[str] = set()

    def _read_backend_register(
        self,
        base_reg: str,
        requested_reg: str | None = None,
    ) -> RegisterObservation:
        raise NotImplementedError

    def _read_backend_memory(self, addr: int, size: int) -> bytes:
        raise NotImplementedError

    def flush_observations(self) -> None:
        self.drop_registers()
        self.mem.drop_all()
        self._observed_register_bases.clear()

    def _cache_register_observation(
        self,
        requested_base: str,
        observation: RegisterObservation,
    ) -> None:
        observed_name = self.arch.to_regname(observation.name)
        if observed_name is None:
            raise RegisterAccessError(
                observation.name,
                f"Backend returned unknown register {observation.name!r}.",
            )
        observed = self.arch.get_reg_accessor(observed_name)
        requested = self.arch.get_reg_accessor(requested_base)
        if observed is None or requested is None:
            raise RegisterAccessError(
                observation.name,
                "Backend register observation has no architecture accessor.",
            )
        if observed.base_reg != requested.base_reg:
            raise RegisterAccessError(
                observation.name,
                f"Backend returned {observed_name} while reading {requested_base}.",
            )
        if observation.num_bits != observed.num_bits:
            raise RegisterAccessError(
                observation.name,
                f"Backend returned {observation.num_bits} bits for {observed_name}; "
                f"the architecture declares {observed.num_bits}.",
            )
        if observation.value < 0 or observation.value >= 1 << observation.num_bits:
            raise RegisterAccessError(
                observation.name,
                f"Backend value does not fit in {observation.num_bits}-bit "
                f"register {observed_name}.",
            )
        if self.arch.register_observation_zero_extends(observed_name):
            self.write_register(requested.base_reg, observation.value)
        else:
            self.write_register(observed_name, observation.value)

    def read_register(self, reg: str) -> int:
        canonical = self.arch.to_regname(reg)
        if canonical is None:
            raise RegisterAccessError(reg, f"Not a register name: {reg}")
        if self.arch.is_constant_register(canonical):
            return ProgramState.read_register(self, canonical)
        if self.test_register(canonical):
            return ProgramState.read_register(self, canonical)

        accessor = self.arch.get_reg_accessor(canonical)
        if accessor is None:
            raise RegisterAccessError(reg, f"Not a register name: {reg}")
        base_reg = accessor.base_reg
        if base_reg not in self._observed_register_bases:
            observation = self._read_backend_register(base_reg, canonical)
            self._cache_register_observation(base_reg, observation)
            self._observed_register_bases.add(base_reg)

        return ProgramState.read_register(self, canonical)

    def read_memory(self, addr: int, size: int) -> bytes:
        if size < 0:
            raise ValueError("A memory read size cannot be negative.")
        if self.mem.test(addr, size):
            return ProgramState.read_memory(self, addr, size)

        data = self._read_backend_memory(addr, size)
        if len(data) != size:
            raise MemoryAccessError(
                addr,
                size,
                f"Backend returned {len(data)} bytes for a {size}-byte read at {hex(addr)}.",
            )
        self.write_memory(addr, data)
        return data
