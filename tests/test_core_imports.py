import subprocess
import sys


CORE_MODULES = (
    "focaccia.arch",
    "focaccia.snapshot",
    "focaccia.trace",
    "focaccia.parser",
    "focaccia.compare",
    "focaccia.match",
    "focaccia.cli",
    "focaccia.reproducer",
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
    script = f"""
import importlib
import sys

for module_name in {CORE_MODULES!r}:
    importlib.import_module(module_name)

for module_name in {INTEGRATION_MODULES!r}:
    assert module_name not in sys.modules, module_name
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
