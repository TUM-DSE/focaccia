from .arch import Arch, ArchitectureKey as ArchitectureKey
from . import x86, aarch64


_x86_64 = x86.ArchX86()
_aarch64_little = aarch64.ArchAArch64("little")
_aarch64_big = aarch64.ArchAArch64("big")

supported_architectures: dict[str, Arch] = {
    "x86_64": _x86_64,
    # `aarch64` is retained as the platform/legacy alias for little endian.
    "aarch64": _aarch64_little,
    _aarch64_little.serialized_name: _aarch64_little,
    _aarch64_big.serialized_name: _aarch64_big,
}
"""Architectures indexed by platform aliases and stable serialized names."""
