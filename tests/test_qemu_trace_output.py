from focaccia.arch import supported_architectures
from focaccia.tools.validate_qemu import make_plugin_trace_environment
from focaccia.trace import TraceEnvironment


def test_plugin_output_uses_typed_guest_trace_environment():
    env = make_plugin_trace_environment("aarch64b")

    assert isinstance(env, TraceEnvironment)
    assert env.binary_name is None
    assert env.binary_hash is None
    assert env.argv == ()
    assert env.envp == ()
    assert env.architecture == supported_architectures["aarch64b"].key
