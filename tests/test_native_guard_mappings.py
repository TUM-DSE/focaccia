from types import SimpleNamespace
from typing import cast

import pytest

from focaccia.native import spec_target
from focaccia.native.lldb_target import ConcreteMemoryError, LLDBLocalTarget


def target_with_guard(monkeypatch, permissions):
    maps = (
        "1000-2000 rw-p 00000000 00:00 0 [heap]\n"
        f"2000-3000 {permissions} 00000000 00:00 0\n"
    )
    monkeypatch.setattr(spec_target, "Path", lambda _: SimpleNamespace(
        is_file=lambda: True, read_text=lambda: maps,
    ))
    debugger_map = SimpleNamespace(start_address=0x1000, end_address=0x2000, perms="rw-")
    target = object.__new__(spec_target.NativeSpecTarget)
    target._closed = False
    # Partial debugger fixture exercises mapping observation only.
    target._target = cast(LLDBLocalTarget, SimpleNamespace(
        process=SimpleNamespace(GetProcessID=lambda: 123),
        get_mappings=lambda: [debugger_map],
        read_memory=lambda address, size: bytes(size),
    ))
    return target


def test_inaccessible_guard_metadata_need_not_have_debugger_readable_region(monkeypatch):
    target = target_with_guard(monkeypatch, "---p")
    mappings = target.mappings()
    assert len(mappings) == 2 and not mappings[1].read
    snapshot = target.memory_snapshot()
    assert len(snapshot.regions) == 1
    assert snapshot.regions[0][0].start == 0x1000


def test_vdso_image_is_not_classified_as_volatile_kernel_data():
    assert "[vdso]" not in spec_target.VOLATILE_MAPPING_NAMES
    assert {"[vvar]", "[vvar_vclock]"} <= spec_target.VOLATILE_MAPPING_NAMES


def test_missing_readable_debugger_mapping_still_fails_closed(monkeypatch):
    target = target_with_guard(monkeypatch, "r--p")
    with pytest.raises(ConcreteMemoryError, match="mapping metadata missing"):
        target.memory_snapshot()
