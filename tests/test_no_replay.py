import pytest
from miasm.expression.expression import ExprId, ExprInt

from focaccia.arch import supported_architectures
from focaccia.arch.arch import ArchitectureKey
from focaccia.no_replay import (
    AnonymousMmapAction,
    ClearChildTidRegistration,
    ExitAction,
    ExitScope,
    MprotectNoneAction,
    NoReplayActionDescriptor,
    NoReplayActionKind,
    NoReplayActionMismatch,
    NoReplayMmapBoundary,
    NoReplayMprotectBoundary,
    SetFsAction,
    SetTidAddressAction,
    UnsupportedNoReplayAction,
    describe_no_replay_action,
    prepare_no_replay_action,
)
from focaccia.qemu.snapshot import collect_snapshot_plan, plan_minimal_snapshot
from focaccia.snapshot import ProgramState, RegisterAccessError
from focaccia.symbolic import (
    EXECUTION_TID,
    SymbolEvaluationError,
    SymbolicTransform,
    allocation_base_symbol,
    eval_symbol,
)


def call(arch_name: str, number: int, argument: int, base: int = 0) -> ProgramState:
    state = ProgramState(supported_architectures[arch_name])
    if arch_name == "x86_64":
        registers = {"RAX": number, "RDI": argument, "RSI": base}
    else:
        registers = {"X8": number, "X0": argument}
    for name, value in registers.items():
        state.write_register(name, value)
    return state


@pytest.mark.parametrize(
    "arch,number,scope",
    [
        ("x86_64", 60, ExitScope.THREAD),
        ("x86_64", 231, ExitScope.GROUP),
        ("aarch64l", 93, ExitScope.THREAD),
        ("aarch64l", 94, ExitScope.GROUP),
        ("aarch64b", 93, ExitScope.THREAD),
        ("aarch64b", 94, ExitScope.GROUP),
    ],
)
@pytest.mark.parametrize("argument", [0, 42, 255, 256, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF])
def test_exit_contract_preserves_argument_scope_and_linux_status(arch, number, scope, argument):
    action = prepare_no_replay_action(call(arch, number, argument), single_thread=True)
    assert isinstance(action, ExitAction)
    assert action.argument == argument
    assert action.scope is scope
    assert action.status == argument % 256
    action.validate_status(argument % 256)
    with pytest.raises(NoReplayActionMismatch):
        action.validate_status((argument + 1) % 256)
    with pytest.raises(UnsupportedNoReplayAction):
        action.validate_status(None)


def test_action_contracts_reject_malformed_types_and_missing_results():
    with pytest.raises(UnsupportedNoReplayAction):
        NoReplayActionDescriptor(
            ArchitectureKey("riscv64", "little"), 0, NoReplayActionKind.EXIT
        )
    with pytest.raises(ValueError):
        NoReplayActionDescriptor(
            ArchitectureKey("x86_64", "little"), 0, "exit"  # pyright: ignore[reportArgumentType]
        )
    with pytest.raises(ValueError):
        SetTidAddressAction(object(), 1)  # pyright: ignore[reportArgumentType]
    with pytest.raises(UnsupportedNoReplayAction):
        AnonymousMmapAction(0)
    with pytest.raises(UnsupportedNoReplayAction):
        AnonymousMmapAction(4096).validate_observed_result(None, lambda _addr, size: bytes(size))
    with pytest.raises(UnsupportedNoReplayAction):
        MprotectNoneAction(0, 0, 4096).validate_return(None)
    with pytest.raises(NoReplayActionMismatch):
        MprotectNoneAction(0, 0, 4096).validate_return(1)


def test_action_boundaries_require_matching_typed_descriptors():
    exit_descriptor = NoReplayActionDescriptor(
        ArchitectureKey("x86_64", "little"), 0x1000, NoReplayActionKind.EXIT
    )
    with pytest.raises(ValueError):
        NoReplayMmapBoundary(0, exit_descriptor, 4096, 0)
    with pytest.raises(ValueError):
        NoReplayMprotectBoundary(0, exit_descriptor, 0, 0, 4096)


def test_equal_exit_codes_do_not_erase_distinct_arguments_or_scopes():
    assert ExitAction(1, ExitScope.THREAD) != ExitAction(257, ExitScope.THREAD)
    assert ExitAction(1, ExitScope.THREAD) != ExitAction(1, ExitScope.GROUP)


@pytest.mark.parametrize("value", [-1, 1 << 64, True, 1.0])
def test_exit_argument_is_strictly_validated(value):
    with pytest.raises(ValueError):
        ExitAction(value, ExitScope.GROUP)


@pytest.mark.parametrize("value", [-1, 256, True, 0.0])
def test_exit_status_must_be_decoded_unsigned_byte(value):
    with pytest.raises(ValueError):
        ExitAction(0, ExitScope.GROUP).validate_status(value)


def test_exit_scope_is_typed():
    with pytest.raises(ValueError):
        ExitAction(0, "group")  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("base", [0, 0x400000, (1 << 47) - 4097])
def test_set_fs_is_derived_from_local_inputs_and_independently_checked(base):
    state = call("x86_64", 158, 0x1002, base)
    action = prepare_no_replay_action(state, single_thread=True)
    assert action == SetFsAction(base)
    assert isinstance(action, SetFsAction)
    action.validate_outputs(0, base)
    assert action.unresolved_register_effects == ("RCX", "R11", "FS")
    # Planning and validating never write observed state, even on a mismatch.
    assert state.read_register("RAX") == 158
    assert state.read_register("RSI") == base
    with pytest.raises(NoReplayActionMismatch):
        action.validate_outputs(0, base + 1)
    with pytest.raises(NoReplayActionMismatch):
        action.validate_outputs((1 << 64) - 1, base)


def test_set_fs_never_requires_native_and_emulated_tls_addresses_to_be_equal():
    native = prepare_no_replay_action(call("x86_64", 158, 0x1002, 0x400000), single_thread=True)
    emulated = prepare_no_replay_action(call("x86_64", 158, 0x1002, 0x700000), single_thread=True)
    assert isinstance(native, SetFsAction) and isinstance(emulated, SetFsAction)
    native.validate_outputs(0, 0x400000)
    emulated.validate_outputs(0, 0x700000)
    with pytest.raises(NoReplayActionMismatch):
        emulated.validate_outputs(0, native.base)


@pytest.mark.parametrize("base", [(1 << 47) - 4096, 1 << 47, (1 << 64) - 1])
def test_set_fs_rejects_unproven_address_ranges(base):
    with pytest.raises(UnsupportedNoReplayAction):
        SetFsAction(base)


@pytest.mark.parametrize("result,base", [(None, 0), (0, None), (None, None)])
def test_set_fs_requires_actual_output_observations(result, base):
    with pytest.raises(UnsupportedNoReplayAction):
        SetFsAction(0).validate_outputs(result, base)


@pytest.mark.parametrize("result,base", [(-1, 0), (True, 0), (0, -1), (0, 1 << 64)])
def test_set_fs_observation_validation_rejects_malformed_values(result, base):
    with pytest.raises(ValueError):
        SetFsAction(0).validate_outputs(result, base)


@pytest.mark.parametrize("operation", [0, 0x1001, 0x1003, 0x1004, 0x1012])
def test_arch_prctl_unknown_get_gs_and_cpuid_variants_reject(operation):
    with pytest.raises(UnsupportedNoReplayAction):
        prepare_no_replay_action(call("x86_64", 158, operation), single_thread=True)


@pytest.mark.parametrize("number", [0, 1, 12, 39, 218, 228, 318, 9999, 0x4000003C])
def test_unknown_nondeterministic_mapping_and_x32_syscalls_reject(number):
    # set_tid_address (218) registers a future kernel write and returns a TID;
    # neither effect is modeled by recognizing a positive return value.
    with pytest.raises(UnsupportedNoReplayAction):
        prepare_no_replay_action(call("x86_64", number, 0), single_thread=True)


def mmap_call(length=8192, **changes):
    state = call("x86_64", 9, 0)
    values = {
        "RDI": 0, "RSI": length, "RDX": 3, "R10": 0x22,
        "R8": 0xFFFFFFFFFFFFFFFF, "R9": 0,
    }
    values.update(changes)
    for name, value in values.items():
        state.write_register(name, value)
    state.write_register("RIP", 0x4018C0)
    return state


def test_anonymous_mmap_contract_uses_local_context_not_oracle_address():
    native = prepare_no_replay_action(mmap_call(), single_thread=True)
    emulated = prepare_no_replay_action(mmap_call(), single_thread=True)
    assert isinstance(native, AnonymousMmapAction)
    assert isinstance(emulated, AnonymousMmapAction)
    assert native == emulated == AnonymousMmapAction(8192)
    assert describe_no_replay_action(mmap_call()).kind is NoReplayActionKind.MMAP_ANONYMOUS_PRIVATE
    assert native.validate_local_result(
        0x70000000, [(0x400000, 0x405000)],
        [(0x70000000, 0x70002000, "rw-p anonymous")],
        lambda _address, size: bytes(size),
    ) == 0x70000000
    assert emulated.validate_local_result(
        0x50000000, [(0x400000, 0x405000)],
        [(0x50000000, 0x50002000, "rw-p anonymous")],
        lambda _address, size: bytes(size),
    ) == 0x50000000


@pytest.mark.parametrize("register,value", [
    ("RDI", 1), ("RDX", 7), ("R10", 0x32), ("R8", 0), ("R9", 4096),
])
def test_anonymous_mmap_rejects_unsupported_variants_before_execution(register, value):
    state = mmap_call(**{register: value})
    with pytest.raises(UnsupportedNoReplayAction):
        describe_no_replay_action(state)
    with pytest.raises(UnsupportedNoReplayAction):
        prepare_no_replay_action(state, single_thread=True)


@pytest.mark.parametrize("failure", ["unaligned", "overlap", "permissions", "short", "nonzero"])
def test_anonymous_mmap_requires_fresh_zero_private_rw_mapping(failure):
    action = AnonymousMmapAction(4097)
    base = 0x70000000
    before = [(base, base + 4096)] if failure == "overlap" else []
    mapping = (base, base + 8192, "rw-p anonymous")
    if failure == "permissions":
        mapping = (base, base + 8192, "rwxp anonymous")
    result = base + 1 if failure == "unaligned" else base
    size = 8191 if failure == "short" else 8192
    byte = b"\1" if failure == "nonzero" else b"\0"
    error = UnsupportedNoReplayAction if failure in ("permissions", "short") else NoReplayActionMismatch
    with pytest.raises(error):
        action.validate_local_result(result, before, [mapping], lambda _address, _size: byte * size)


@pytest.mark.parametrize("number", [158, 96, 172, 278])
def test_x86_policy_numbers_do_not_leak_to_aarch64(number):
    with pytest.raises(UnsupportedNoReplayAction):
        prepare_no_replay_action(call("aarch64l", number, 0x1002), single_thread=True)


@pytest.mark.parametrize("proven_single_thread", [False, None, 1])
def test_single_thread_precondition_is_not_inferred(proven_single_thread):
    with pytest.raises(UnsupportedNoReplayAction):
        prepare_no_replay_action(call("x86_64", 60, 0), single_thread=proven_single_thread)


def test_missing_registers_remain_unknown_and_unused_registers_are_not_required():
    state = ProgramState(supported_architectures["x86_64"])
    with pytest.raises(RegisterAccessError):
        prepare_no_replay_action(state, single_thread=True)
    state.write_register("RAX", 60)
    with pytest.raises(RegisterAccessError):
        prepare_no_replay_action(state, single_thread=True)
    state.write_register("RDI", 0)
    assert prepare_no_replay_action(state, single_thread=True) == ExitAction(0, ExitScope.THREAD)


@pytest.mark.parametrize("arch,number", [("x86_64", 218), ("aarch64l", 96), ("aarch64b", 96)])
@pytest.mark.parametrize("address", [0, 0x400000, (1 << 64) - 1])
def test_set_tid_address_keeps_registration_separate_from_return(arch, number, address):
    state = call(arch, number, address)
    with pytest.raises(UnsupportedNoReplayAction):
        prepare_no_replay_action(state, single_thread=True)
    action = prepare_no_replay_action(state, single_thread=True, expected_tid=1234)
    assert isinstance(action, SetTidAddressAction)
    assert action.registration == ClearChildTidRegistration(address)
    action.validate_return(1234)
    with pytest.raises(NoReplayActionMismatch):
        action.validate_return(4321)
    with pytest.raises(UnsupportedNoReplayAction):
        action.validate_return(None)
    # Registration does not imply dereferencing the pointer or writing memory.
    assert action.registration.address == address


def test_tid_context_is_local_not_copied_from_native_outputs():
    native = prepare_no_replay_action(
        call("x86_64", 218, 0x400000), single_thread=True, expected_tid=123
    )
    emulated = prepare_no_replay_action(
        call("x86_64", 218, 0x700000), single_thread=True, expected_tid=456
    )
    assert isinstance(native, SetTidAddressAction) and isinstance(emulated, SetTidAddressAction)
    native.validate_return(123)
    emulated.validate_return(456)
    # Both local predicates hold, but different TIDs remain distinct effects:
    # this does not establish the paper's same-action equivalence criterion.
    assert native != emulated
    assert native.expected_tid != emulated.expected_tid
    with pytest.raises(NoReplayActionMismatch):
        emulated.validate_return(native.expected_tid)


@pytest.mark.parametrize("tid", [0, -1, 1 << 31, True, 3.0])
def test_tid_context_is_a_strict_positive_pid_t(tid):
    with pytest.raises(ValueError):
        SetTidAddressAction(ClearChildTidRegistration(0), tid)


@pytest.mark.parametrize("address", [-1, 1 << 64, True])
def test_tid_registration_address_must_be_a_known_pointer(address):
    with pytest.raises(ValueError):
        ClearChildTidRegistration(address)


@pytest.mark.parametrize("result", [-1, 1 << 64, True])
def test_tid_return_must_be_a_well_formed_register_value(result):
    with pytest.raises(ValueError):
        SetTidAddressAction(ClearChildTidRegistration(0), 123).validate_return(result)


@pytest.mark.parametrize(
    "number,argument,kind",
    [
        (60, 42, NoReplayActionKind.EXIT),
        (231, 42, NoReplayActionKind.EXIT_GROUP),
        (158, 0x1002, NoReplayActionKind.SET_FS),
        (218, 0x400000, NoReplayActionKind.SET_TID_ADDRESS),
    ],
)
def test_descriptor_contains_only_policy_architecture_and_boundary(number, argument, kind):
    state = call("x86_64", number, argument, 0x400000)
    state.write_register("PC", 0x401000)
    descriptor = describe_no_replay_action(state)
    assert descriptor == NoReplayActionDescriptor(state.arch.key, 0x401000, kind)
    # No recorded return or argument values are needed to serialize the descriptor.
    assert descriptor.__slots__ == ("architecture", "pc", "kind")
    prepare_no_replay_action(state, single_thread=True, expected_tid=123, descriptor=descriptor)
    state.write_register("PC", 0x401002)
    with pytest.raises(NoReplayActionMismatch):
        prepare_no_replay_action(state, single_thread=True, expected_tid=123, descriptor=descriptor)


def test_same_descriptor_instantiates_distinct_local_tls_arguments():
    native = call("x86_64", 158, 0x1002, 0x400000)
    emulated = call("x86_64", 158, 0x1002, 0x700000)
    for state in (native, emulated):
        state.write_register("PC", 0x401000)
    descriptor = describe_no_replay_action(native)
    assert describe_no_replay_action(emulated) == descriptor
    action = prepare_no_replay_action(emulated, single_thread=True, descriptor=descriptor)
    assert action == SetFsAction(0x700000)
    # Same PC but different policy cannot consume the expected action boundary.
    emulated.write_register("RAX", 231)
    with pytest.raises(NoReplayActionMismatch):
        prepare_no_replay_action(emulated, single_thread=True, descriptor=descriptor)
    emulated.write_register("RAX", 9999)
    with pytest.raises(UnsupportedNoReplayAction):
        prepare_no_replay_action(emulated, single_thread=True, descriptor=descriptor)


@pytest.mark.parametrize(
    "arch,number,kind",
    [
        ("aarch64l", 93, NoReplayActionKind.EXIT),
        ("aarch64b", 94, NoReplayActionKind.EXIT_GROUP),
        ("aarch64l", 96, NoReplayActionKind.SET_TID_ADDRESS),
    ],
)
def test_aarch64_descriptor_uses_guest_abi_and_endianness(arch, number, kind):
    state = call(arch, number, 0)
    state.write_register("PC", 0x401000)
    assert describe_no_replay_action(state) == NoReplayActionDescriptor(
        state.arch.key, 0x401000, kind
    )
    with pytest.raises(UnsupportedNoReplayAction):
        NoReplayActionDescriptor(state.arch.key, 0x401000, NoReplayActionKind.SET_FS)


@pytest.mark.parametrize('failure', [None, 'missing', 'arch', 'entry', 'hash', 'short', 'type', 'headers', 'interpreter'])
def test_no_replay_static_entry_hash_contract(tmp_path, failure):
    import struct
    from focaccia.arch.arch import ArchitectureKey
    from focaccia.no_replay import require_exit_only_entry
    from focaccia.utils import file_hash
    data = bytearray(120)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', data, 16, 2, 62)
    struct.pack_into('<QQ', data, 24, 0x1000, 64)
    struct.pack_into('<HH', data, 54, 56, 1)
    struct.pack_into('<I', data, 64, 3 if failure == 'interpreter' else 1)
    if failure == 'short':
        data = data[:32]
    elif failure == 'type':
        struct.pack_into('<H', data, 16, 3)
    elif failure == 'headers':
        struct.pack_into('<H', data, 56, 2)
    path = tmp_path / 'fixture.elf'
    path.write_bytes(data)
    args = (None if failure == 'missing' else str(path),
            'bad' if failure == 'hash' else file_hash(str(path)),
            0x1001 if failure == 'entry' else 0x1000,
            ArchitectureKey('aarch64' if failure == 'arch' else 'x86_64', 'little'))
    if failure:
        with pytest.raises(UnsupportedNoReplayAction):
            require_exit_only_entry(*args)
    else:
        require_exit_only_entry(*args)


def set_fs_states(base=0x404178):
    before = call('x86_64', 158, 0x1002, base)
    after = call('x86_64', 0, 0x1002, base)
    for state in (before, after):
        for name in (
            'RBX', 'RCX', 'RDX', 'RBP', 'RSP', 'FS', 'FS_BASE', 'GS', 'GS_BASE',
            *[f'R{i}' for i in range(8, 16)],
        ):
            state.write_register(name, 0)
        state.write_register('RFLAGS', 0x202)
    before.write_register('RIP', 0x4017c0)
    before.write_memory(0x4017c0, b'\x0f\x05')
    after.write_register('RIP', 0x4017c2)
    after.write_register('RCX', 0x4017c2)
    after.write_register('R11', 0x202)
    after.write_register('FS_BASE', base)
    return before, after


@pytest.mark.parametrize('register', [None, 'RAX', 'FS_BASE', 'FS', 'RCX', 'R11', 'RFLAGS', 'RIP', 'RBX', 'RDI'])
def test_set_fs_full_local_transition(register):
    from focaccia.no_replay import snapshot_set_fs_inputs, validate_set_fs_transition
    before, after = set_fs_states()
    frozen = snapshot_set_fs_inputs(before)
    if register is not None:
        after.write_register(register, after.read_register(register) ^ 1)
        with pytest.raises(NoReplayActionMismatch):
            validate_set_fs_transition(frozen, after)
    else:
        assert validate_set_fs_transition(frozen, after) == SetFsAction(0x404178)


def test_set_fs_effect_allows_matcher_to_report_known_register_mismatch():
    from focaccia.no_replay import validate_set_fs_effect, validate_set_fs_transition

    before, after = set_fs_states()
    after.write_register('R11', 0)
    assert validate_set_fs_effect(before, after) == SetFsAction(0x404178)
    with pytest.raises(NoReplayActionMismatch, match='R11'):
        validate_set_fs_transition(before, after)


@pytest.mark.parametrize('register,value', [('FS', 1), ('RFLAGS', 0x302), ('RFLAGS', 0x10202)])
def test_set_fs_unsupported_prestate_rejects(register, value):
    from focaccia.no_replay import snapshot_set_fs_inputs, validate_set_fs_transition
    before, after = set_fs_states()
    before.write_register(register, value)
    with pytest.raises(UnsupportedNoReplayAction):
        snapshot_set_fs_inputs(before)
    with pytest.raises(UnsupportedNoReplayAction):
        validate_set_fs_transition(before, after)


@pytest.mark.parametrize('emulator_tid', [92759, 92760])
def test_inventory_tid_local_success_is_not_same_action_support(emulator_tid):
    from focaccia.no_replay import require_same_no_replay_action
    # Concrete native inventory: libc1372 returned its independent inferior PID92759.
    native = SetTidAddressAction(ClearChildTidRegistration(0x4042b0), 92759)
    emulated = SetTidAddressAction(ClearChildTidRegistration(0x4042b0), emulator_tid)
    native.validate_return(92759)
    emulated.validate_return(emulator_tid)
    message = 'unobserved' if emulator_tid == 92759 else 'Different independently'
    with pytest.raises(UnsupportedNoReplayAction, match=message):
        require_same_no_replay_action(native, emulated)


def test_same_set_fs_effect_requires_equal_instantiated_base():
    from focaccia.no_replay import require_same_no_replay_action, validate_set_fs_transition
    native = validate_set_fs_transition(*set_fs_states(0x404178))
    emulated = validate_set_fs_transition(*set_fs_states(0x504178))
    with pytest.raises(UnsupportedNoReplayAction, match='Different independently'):
        require_same_no_replay_action(native, emulated)
    require_same_no_replay_action(native, native)


EXECUTION_TID_ARCH = supported_architectures["x86_64"]


def execution_tid_transform(outputs, start=0x1000):
    return SymbolicTransform(999, outputs, [], EXECUTION_TID_ARCH, start, start + 1)


def test_execution_tid_is_independent_of_registers_and_transform_tid():
    state = ProgramState(EXECUTION_TID_ARCH, execution_tid=123)
    state.write_register("RAX", 456)
    item = execution_tid_transform({ExprId("RAX", 64): EXECUTION_TID})
    assert eval_symbol(item.changed_regs["RAX"], state) == 123
    with pytest.raises(RegisterAccessError):
        state.read_register(EXECUTION_TID.name)
    assert EXECUTION_TID.name not in state.regs


@pytest.mark.parametrize("value", [0, -1, 1 << 31, True, 1.5, "123"])
def test_execution_tid_rejects_invalid_context(value):
    with pytest.raises(ValueError, match="Execution TID"):
        ProgramState(EXECUTION_TID_ARCH, execution_tid=value)
    state = ProgramState(EXECUTION_TID_ARCH)
    with pytest.raises(ValueError, match="Execution TID"):
        state.execution_tid = value


def test_execution_tid_missing_and_wrong_width_fail_closed():
    state = ProgramState(EXECUTION_TID_ARCH)
    state.write_register("RAX", 123)
    with pytest.raises(SymbolEvaluationError, match="missing"):
        eval_symbol(EXECUTION_TID, state)
    state.execution_tid = (1 << 31) - 1
    assert eval_symbol(EXECUTION_TID, state) == (1 << 31) - 1
    with pytest.raises(SymbolEvaluationError, match="width"):
        eval_symbol(ExprId(EXECUTION_TID.name, 32), state)


def test_anonymous_mmap_mprotect_is_local_allocation_relative():
    for base in (0x50000000, 0x70000000):
        state = mmap_call()
        state.allocation_bases = (base,)
        state.write_register("RAX", 10)
        state.write_register("RDI", base + 4096)
        state.write_register("RSI", 4096)
        state.write_register("RDX", 0)
        state.write_register("RIP", 0x401987)
        action = prepare_no_replay_action(state, single_thread=True)
        assert isinstance(action, MprotectNoneAction)
        assert action == MprotectNoneAction(0, 4096, 4096)
        assert describe_no_replay_action(state).kind is NoReplayActionKind.MPROTECT_NONE_PAGE
        action.validate_return(0)
    invalid = mmap_call()
    invalid.allocation_bases = (0x70000000,)
    invalid.write_register("RAX", 10)
    invalid.write_register("RDI", 0x70000000)
    invalid.write_register("RSI", 4096)
    invalid.write_register("RDX", 0)
    with pytest.raises(UnsupportedNoReplayAction):
        prepare_no_replay_action(invalid, single_thread=True)


def test_anonymous_mmap_allocation_context_is_local_composable_and_fail_closed():
    symbol = allocation_base_symbol(0)
    native = ProgramState(EXECUTION_TID_ARCH, allocation_bases=(0x70000000,))
    emulated = ProgramState(EXECUTION_TID_ARCH, allocation_bases=(0x50000000,))
    assert eval_symbol(symbol + ExprInt(4088, 64), native) == 0x70000FF8
    assert eval_symbol(symbol + ExprInt(4088, 64), emulated) == 0x50000FF8
    with pytest.raises(SymbolEvaluationError, match="allocation context"):
        eval_symbol(symbol, ProgramState(EXECUTION_TID_ARCH))
    transform = SymbolicTransform(
        1, {ExprId("RAX", 64): symbol}, [], EXECUTION_TID_ARCH, 0x1000, 0x1001
    )
    following = SymbolicTransform(
        1, {ExprId("RBX", 64): ExprId("RAX", 64) + ExprInt(4088, 64)}, [],
        EXECUTION_TID_ARCH, 0x1001, 0x1002,
    )
    composed = transform.composed_with(following)
    assert eval_symbol(composed.canonical_register_outputs()["RBX"], emulated) == 0x50000FF8


def test_execution_tid_survives_composition_and_snapshot_collection():
    first = execution_tid_transform({ExprId("RAX", 64): EXECUTION_TID})
    second = execution_tid_transform(
        {ExprId("RBX", 64): ExprId("RAX", 64) + ExprInt(1, 64)}, 0x1001
    )
    composed = first.composed_with(second)
    assert EXECUTION_TID.name not in composed.get_used_registers()
    assert EXECUTION_TID.name not in composed.get_validation_input_registers()
    previous = ProgramState(EXECUTION_TID_ARCH, execution_tid=111)
    current = ProgramState(EXECUTION_TID_ARCH, execution_tid=222)
    current.write_register("PC", 0x1000)
    plan = plan_minimal_snapshot(current, None, composed)
    assert EXECUTION_TID.name not in plan.registers
    collection = collect_snapshot_plan(previous, current, plan)
    assert not collection.issues
    assert collection.state.execution_tid == 222
    assert eval_symbol(composed.canonical_register_outputs()["RBX"], collection.state) == 223
    current.execution_tid = None
    missing = collect_snapshot_plan(previous, current, plan).state
    assert missing.execution_tid is None
    with pytest.raises(SymbolEvaluationError, match="missing"):
        eval_symbol(EXECUTION_TID, missing)
