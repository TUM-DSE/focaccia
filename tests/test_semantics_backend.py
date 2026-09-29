import pytest

from focaccia.tools.capture_transforms import create_symbolic_tracer, make_argparser
from focaccia.trace import TraceEnvironment


def test_default_and_explicit_miasm_selection_preserves_factory_arguments():
    env = TraceEnvironment("/tmp/oracle", (), (), binary_hash="fixture")
    calls = []

    def factory(actual_env, **kwargs):
        calls.append((actual_env, kwargs))
        return object()

    defaults = make_argparser().parse_args(["/tmp/oracle"])
    explicit = make_argparser().parse_args(["--semantics-backend", "miasm", "/tmp/oracle"])
    create_symbolic_tracer(defaults, env, factory)
    create_symbolic_tracer(explicit, env, factory)
    assert calls[0][1] == calls[1][1]
    assert "semantics_backend" not in calls[0][1]


def test_tir_selection_lazily_constructs_adapter(monkeypatch):
    from focaccia import tir_backend

    instance = object()
    monkeypatch.setattr(tir_backend, "TirBackend", lambda: instance)
    env = TraceEnvironment("/tmp/oracle", (), (), binary_hash="fixture")
    args = make_argparser().parse_args(["--semantics-backend", "tir", "/tmp/oracle"])
    calls = []
    create_symbolic_tracer(args, env, lambda actual_env, **kwargs: calls.append(kwargs) or instance)
    assert calls[0]["semantics_backend"] is instance


def test_alternative_backend_cannot_use_miasm_native_mrs_shortcut(monkeypatch, tmp_path):
    from test_native_dczid_observation import NativeMrsTarget, capture
    from focaccia.symbolic import UnsupportedInstructionError

    class Backend:
        name = "fixture"

        def generate(self, instruction, state, context):
            raise UnsupportedInstructionError("MRS unsupported by fixture backend")

    target = NativeMrsTarget()
    tracer = capture(monkeypatch, tmp_path, target)
    tracer.semantics_backend = Backend()
    monkeypatch.setattr(
        tracer,
        "_observe_native_dczid_mrs",
        lambda *args: pytest.fail("Miasm-only native shortcut used"),
    )
    with pytest.raises(UnsupportedInstructionError, match="MRS unsupported"):
        tracer.trace()
    assert target.steps == []
