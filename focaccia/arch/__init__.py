from .arch import Arch
from . import x86

"""A dictionary containing all supported architectures at their names.

The arch names (keys) should be compatible with the string returned from
`platform.machine()`.
"""
supported_architectures: dict[str, Arch] = {
    "x86_64": x86.ArchX86(),
}
