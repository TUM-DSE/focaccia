import pytest

from focaccia.native import spec_target
from focaccia.native.lldb_target import ConcreteExecutionError


def target_with_output(tmp_path):
    target = object.__new__(spec_target.NativeSpecTarget)
    target._stdout_path = str(tmp_path / "stdout")
    target._stderr_path = str(tmp_path / "stderr")
    target._stdout = target._stderr = b""
    return target


def test_missing_terminal_output_is_not_evidence_of_empty_output(tmp_path):
    target = target_with_output(tmp_path)
    with pytest.raises(ConcreteExecutionError, match="Missing native output evidence"):
        target._capture_output(required=True)
    # A failed launch may have no files; best-effort cleanup must still work.
    target._capture_output()


def test_both_output_streams_are_required_and_bounded(tmp_path, monkeypatch):
    target = target_with_output(tmp_path)
    (tmp_path / "stdout").write_bytes(b"abc")
    with pytest.raises(ConcreteExecutionError, match="Missing native output evidence"):
        target._capture_output(required=True)
    (tmp_path / "stderr").write_bytes(b"")
    target._capture_output(required=True)
    assert target.stdout == b"abc" and target.stderr == b""
    monkeypatch.setattr(spec_target, "MAX_OUTPUT_BYTES", 2)
    with pytest.raises(ConcreteExecutionError, match="capture limit"):
        target._capture_output(required=True)
