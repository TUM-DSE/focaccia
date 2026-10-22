import json
from types import SimpleNamespace
from typing import Any, MutableMapping, cast

from focaccia.arch import Arch

import pytest

from focaccia.native import spec_target
from focaccia.native.lldb_target import ConcreteExecutionError, LLDBLocalTarget


def mock_capture(tmp_path, monkeypatch, **changes):
    target = object.__new__(spec_target.NativeSpecTarget)
    target._closed = False
    # Only presence and architecture name are used by this capture fixture.
    target._target = cast(LLDBLocalTarget, object())
    target.arch = cast(Arch, SimpleNamespace(archname="aarch64"))
    target.pid = 42
    target.hardware_profile = None
    helper = tmp_path / "helper"
    helper.write_bytes(b"profile-helper-fixture")
    affinity = {42: {3, 5}}
    monkeypatch.setattr(spec_target.os, "sched_getaffinity", lambda pid: affinity[pid])
    monkeypatch.setattr(spec_target.os, "sched_setaffinity", lambda pid, mask: affinity.update({pid: mask}))
    evidence = {"schema": 1, "architecture": "aarch64", "cpu": 3, "dczid_el0": 4, **changes}

    def run(command, **kwargs):
        assert command == [str(helper), "--cpu", "3"]
        assert affinity[42] == {3}
        return SimpleNamespace(returncode=0, stdout=json.dumps(evidence).encode(), stderr=b"")

    monkeypatch.setattr(spec_target.subprocess, "run", run)
    return target, helper


def test_hardware_config_is_independent_pre_input_on_pinned_cpu(tmp_path, monkeypatch):
    target, helper = mock_capture(tmp_path, monkeypatch)
    profile = target.configure_arm_profile(str(helper))
    assert profile["cpu"] == 3 and profile["dczid_el0"] == 4
    assert len(profile["helper_sha256"]) == 64
    profile["dczid_el0"] = 7
    assert target.hardware_profile is not None
    assert target.hardware_profile["dczid_el0"] == 4
    with pytest.raises(TypeError):
        # Deliberately attempt a write to verify runtime immutability.
        cast(MutableMapping[str, Any], target.hardware_profile)["dczid_el0"] = 7
    with pytest.raises(ConcreteExecutionError, match="repeated"):
        target.configure_arm_profile(str(helper))


@pytest.mark.parametrize("changes", [
    {"cpu": 5}, {"cpu": True}, {"schema": True}, {"architecture": "x86_64"},
    {"dczid_el0": -1}, {"dczid_el0": 32}, {"dczid_el0": 15},
    {"dczid_el0": 31}, {"dczid_el0": True}, {"unexpected": 1},
])
def test_hardware_config_mismatch_or_invalid_evidence_fails_closed(tmp_path, monkeypatch, changes):
    target, helper = mock_capture(tmp_path, monkeypatch, **changes)
    with pytest.raises(ConcreteExecutionError, match="Invalid hardware-profile"):
        target.configure_arm_profile(str(helper))
    assert target.hardware_profile is None
