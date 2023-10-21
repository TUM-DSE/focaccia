from .arch import Arch
from . import x86

"""A dictionary containing all supported architectures at their names."""
supported_architectures: dict[str, Arch] = {
    "X86": x86.ArchX86(),
}
