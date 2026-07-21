import pytest
from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch import ArchitectureKey, aarch64, supported_architectures, x86
from focaccia.native.lldb_target import LLDBConcreteTarget
from focaccia.qemu.deterministic import syscall_number_registers
from focaccia.snapshot import ProgramState
from focaccia.symbolic import SymbolicTransform


def test_architecture_identity_includes_endianness_and_serialized_name():
    little = supported_architectures["aarch64l"]
    big = supported_architectures["aarch64b"]

    assert supported_architectures["aarch64"] is little
    assert little.key == ArchitectureKey("aarch64", "little")
    assert big.key == ArchitectureKey("aarch64", "big")
    assert little.serialized_name == "aarch64l"
    assert big.serialized_name == "aarch64b"
    assert little != big
    assert little == aarch64.ArchAArch64("little")


def test_symbolic_serialization_uses_stable_architecture_identity():
    for architecture_name in ("aarch64l", "aarch64b"):
        arch = supported_architectures[architecture_name]
        transform = SymbolicTransform(1, {}, [], arch, 0x1000, 0x1004)

        encoded = transform.to_json()
        decoded = SymbolicTransform.from_json(encoded)

        assert encoded["arch"] == architecture_name
        assert decoded.arch == arch


def test_x86_multibit_iopl_round_trip():
    for iopl in range(4):
        encoded = x86.compose_rflags({"IOPL": iopl, "ZF": 1})
        fields = x86.decompose_rflags(encoded)

        assert fields["IOPL"] == iopl
        assert fields["ZF"] == 1

        state = ProgramState(x86.ArchX86())
        state.write_register("RFLAGS", encoded)
        assert state.read_register("IOPL") == iopl

    with pytest.raises(ValueError):
        x86.compose_rflags({"IOPL": 4})


def test_aarch64_multibit_status_fields_round_trip():
    for ge in range(16):
        for mode in range(16):
            encoded = aarch64.compose_cpsr({"GE": ge, "M": mode, "Z": 1})
            fields = aarch64.decompose_cpsr(encoded)
            assert fields["GE"] == ge
            assert fields["M"] == mode
            assert fields["Z"] == 1

    with pytest.raises(ValueError):
        aarch64.compose_cpsr({"GE": 16})


def test_aarch64_zero_registers_are_constants():
    arch = aarch64.ArchAArch64("little")
    state = ProgramState(arch)

    assert "XZR" not in state.regs
    assert "XZR" not in arch.regnames
    assert {"XZR", "WZR"}.issubset(arch.all_regnames)
    assert state.test_register("XZR")
    assert state.read_register("XZR") == 0
    assert state.read_register("WZR") == 0
    assert state.read_register("RZR") == 0

    state.write_register("XZR", 0xFFFFFFFFFFFFFFFF)
    state.write_register_zero_extended("WZR", 0xFFFFFFFF)
    assert state.read_register("XZR") == 0
    assert state.read_register("WZR") == 0


def test_aarch64_zero_register_bypasses_lldb(monkeypatch):
    target = object.__new__(LLDBConcreteTarget)
    target.arch = aarch64.ArchAArch64('little')
    target.archname = aarch64.archname

    def unexpected_access(_regname: str):
        raise AssertionError('Constant registers must not be read from LLDB')

    monkeypatch.setattr(target, '_get_register', unexpected_access)
    assert target.read_register('XZR') == 0
    assert target.read_register('WZR') == 0
    target.write_register('XZR', 42)


def test_aarch64_status_register_is_32_bits():
    arch = aarch64.ArchAArch64("little")
    cpsr = arch.get_reg_accessor("CPSR")
    assert cpsr is not None
    assert cpsr.num_bits == 32


def test_symbolic_writes_to_aarch64_zero_register_are_discarded():
    arch = aarch64.ArchAArch64("little")
    transform = SymbolicTransform(
        1,
        {ExprId("RZR", 64): ExprInt(42, 64)},
        [],
        arch,
        0x1000,
        0x1004,
    )
    assert transform.changed_regs == {}


@pytest.mark.parametrize(
    "arch",
    [x86.ArchX86(), aarch64.ArchAArch64("little"), aarch64.ArchAArch64("big")],
)
def test_all_registered_register_accessors_round_trip(arch):
    for regname in arch.all_regnames:
        state = ProgramState(arch)
        accessor = arch.get_reg_accessor(regname)
        assert accessor is not None

        alias_value = (1 << accessor.num_bits) - 1
        state.write_register(regname, alias_value)
        if arch.is_constant_register(regname):
            assert state.read_register(regname) == arch.get_constant_register_value(regname)
            continue
        assert state.read_register(regname) == alias_value

        base = arch.get_reg_accessor(accessor.base_reg)
        assert base is not None
        state = ProgramState(arch)
        state.write_register(accessor.base_reg, (1 << base.num_bits) - 1)
        assert state.read_register(regname) == alias_value


def test_syscall_replay_policy_lives_in_qemu_backend():
    for arch in set(supported_architectures.values()):
        assert not hasattr(arch, "get_em_syscalls")
        assert not hasattr(arch, "get_pasthru_syscalls")
        assert not hasattr(arch, "get_syscall_reg")

    assert syscall_number_registers == {"x86_64": "rax"}
