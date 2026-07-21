import importlib
import sys


CORE_MODULES = (
    "focaccia.arch",
    "focaccia.snapshot",
    "focaccia.trace",
    "focaccia.parser",
    "focaccia.compare",
    "focaccia.match",
)

INTEGRATION_MODULES = (
    "lldb",
    "gdb",
    "focaccia.native",
    "focaccia.qemu",
    "focaccia.deterministic",
    "focaccia._deterministic_impl",
)


def test_core_modules_import_without_integration_backends():
    for module_name in CORE_MODULES:
        importlib.import_module(module_name)

    for module_name in INTEGRATION_MODULES:
        assert module_name not in sys.modules
