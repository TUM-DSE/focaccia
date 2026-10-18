from miasm.expression.expression import ExprCond, ExprId, ExprInt, ExprMem, ExprOp
from types import SimpleNamespace

import pytest

from focaccia.boundary_oracle import predict
from focaccia.intel_symbolic import (
    GPR_OUTPUTS, PROFILE, REQUIRED_OUTPUTS, IntelInstructionResidual,
    IntelOrderedEffect, IntelProjectedReadEffect, IntelReadEffect, IntelPreBoundaryState,
    IntelSymbolicBackend, SymbolicIntelLiveModel, SymbolicTransformComposer,
    compare_intel_boundary, compose_intel_residuals, decode_intel_residual,
    knownness_inputs_for_observation, normalize_observed_registers,
    capture_projected_intel_read_effects, predict_intel_transform,
    project_intel_read_effects, predict_residual_control,
    predict_syscall_prestate,
)
from focaccia.snapshot import MemoryAccessError
from focaccia.symbolic import SymbolEvaluationError, SymbolicTransform


def observations():
    result = {name: index + 1 for index, name in enumerate(GPR_OUTPUTS)}
    result.update(RIP=0x1000, RFLAGS=0x202, FS_BASE=0x10000, GS_BASE=0x20000)
    result.update({f"XMM{i}": i + 0x1234 for i in range(16)})
    return result


def reg(name, width):
    return {"kind": "register", "bits": width, "name": name}


def const(value, width):
    return {"kind": "constant", "bits": width, "value": f"0x{value:x}"}


def memory_after(prefix, width=8):
    return {"kind": "memory_after", "bits": width, "address": reg("RAX", 64),
            "prefix": prefix}


def residual_document(*, effects=None, outputs=None, control=None):
    model_hash = "a" * 64
    outputs = outputs or {"RIP": const(0x1001, 64)}
    return model_hash, {
        "schema": 2, "architecture": "x86_64", "profile": PROFILE,
        "pc": "4096", "code": "90", "iform": "NOP_90", "model_sha256": model_hash,
        "status": "ok", "outputs": outputs,
        "defined_masks": {name: const((1 << value["bits"]) - 1, value["bits"])
                           for name, value in outputs.items()},
        "guards": [], "ordered_effects": effects or [],
        "control": control or {"next_ip": const(0x1001, 64), "repeat": const(0, 1),
                               "environment_cutpoint": const(0, 1)},
        "control_masks": {"next_ip": const((1 << 64) - 1, 64), "repeat": const(1, 1),
                          "environment_cutpoint": const(1, 1)},
        "syscall_pre": {}, "syscall_pre_masks": {},
    }


def test_intel_register_contract_and_knownness_policy():
    observed = observations()
    known = knownness_inputs_for_observation(observed)
    assert tuple(REQUIRED_OUTPUTS[:16]) == GPR_OUTPUTS
    assert known["RAX"] == (1 << 64) - 1
    assert known["RFLAGS"] == (1 << 64) - 1
    assert known["ZMM0"] == (1 << 128) - 1
    assert known["ZMM0"] >> 128 == 0


def test_residual_is_source_owned_and_masks_are_explicit():
    expr = ExprId("RAX", 64) + ExprInt(1, 64)
    residual = IntelInstructionResidual(
        0x1000, 1, {"RAX": expr}, {"RAX": ExprInt((1 << 64) - 1, 64)},
    )
    transform = residual.to_transform(1)
    assert transform.source_owned
    with pytest.raises(SymbolEvaluationError, match="Source-owned"):
        transform.validation_register_outputs()


def test_transform_importer_drops_only_true_identity_value_and_mask_pairs():
    observed = observations()
    residual = IntelInstructionResidual(0x1000, 1,
        {"RAX": ExprId("RAX", 64), "XMM0": ExprId("XMM0", 128),
         "RIP": ExprInt(0x1001, 64)},
        {"RAX": ExprId("__focaccia_known_RAX", 64),
         "XMM0": ExprId("__focaccia_known_ZMM0", 512)[0:128],
         "RIP": ExprInt((1 << 64) - 1, 64)})
    transform = residual.to_transform(4)
    assert "RAX" not in transform.changed_regs
    assert "XMM0" not in transform.changed_regs
    state = IntelPreBoundaryState(observed, lambda *_: b"", lambda *_: 11)
    prediction = predict_intel_transform(transform, state,
                                        knownness_inputs_for_observation(observed))
    assert prediction.registers["RAX"].value == observed["RAX"]
    assert prediction.registers["XMM0"].value == observed["XMM0"]
    # A full constant source mask is a real definition even when value identity.
    defined_identity = IntelInstructionResidual(0x1000, 1,
        {"RAX": ExprId("RAX", 64)}, {"RAX": ExprInt((1 << 64) - 1, 64)})
    assert "RAX" in defined_identity.to_transform(4).changed_regs


def test_complete_source_view_includes_unchanged_gprs_xmm_and_segment_bases():
    observed = observations()
    state = IntelPreBoundaryState(observed, lambda *_: b"", lambda *_: 11)
    residual = IntelInstructionResidual(0x1000, 1,
        {"RAX": ExprId("RAX", 64) + ExprInt(1, 64)},
        {"RAX": ExprInt((1 << 64) - 1, 64)})
    prediction = predict_intel_transform(residual.to_transform(7), state,
                                        knownness_inputs_for_observation(observed))
    assert set(prediction.registers) == set(REQUIRED_OUTPUTS)
    actual = normalize_observed_registers(observed)
    assert prediction.registers["RAX"].value == observed["RAX"] + 1
    for name in REQUIRED_OUTPUTS:
        if name != "RAX":
            assert prediction.registers[name].value == actual[name]
    actual["RAX"] = prediction.registers["RAX"].value
    assert compare_intel_boundary(prediction, actual, {}, set()).ok
    for register in ("RAX", "RIP", "XMM0", "FS_BASE", "GS_BASE"):
        corrupt = dict(actual)
        corrupt[register] ^= 1
        assert not compare_intel_boundary(prediction, corrupt, {}, set()).ok
    assert not compare_intel_boundary(prediction, actual, {}, {0x9000}).ok
    unknown = knownness_inputs_for_observation(observed)
    unknown["ZMM0"] = 0
    unknown_prediction = predict_intel_transform(residual.to_transform(7), state, unknown)
    with pytest.raises(ValueError, match="excluded from observation"):
        compare_intel_boundary(unknown_prediction, actual, {}, set())


def test_defined_flag_mask_is_compared_but_undefined_af_is_exempt():
    observed = observations()
    state = IntelPreBoundaryState(observed, lambda *_: b"", lambda *_: 11)
    full = (1 << 64) - 1
    residual = IntelInstructionResidual(0x1000, 1, {"RFLAGS": ExprId("RFLAGS", 64)},
        {"RFLAGS": ExprInt(full ^ (1 << 4), 64)})
    prediction = predict_intel_transform(residual.to_transform(1), state,
                                        knownness_inputs_for_observation(observed))
    actual = normalize_observed_registers(observed)
    actual["RFLAGS"] ^= 1 << 4
    assert compare_intel_boundary(prediction, actual, {}, set()).ok
    actual["RFLAGS"] ^= 1 << 0
    assert not compare_intel_boundary(prediction, actual, {}, set()).ok


def test_source_control_and_syscall_prestate_use_shared_prediction():
    observed = observations()
    state = IntelPreBoundaryState(observed, lambda *_: b"", lambda *_: 11)
    controls = {
        "next_ip": ExprInt(0x1001, 64), "repeat": ExprInt(1, 1),
        "environment_cutpoint": ExprInt(0, 1), "syscall_pre.RAX": ExprId("RAX", 64),
    }
    masks = {name: ExprInt((1 << expr.size) - 1, expr.size)
             for name, expr in controls.items()}
    residual = IntelInstructionResidual(0x1000, 1, {"RIP": ExprInt(0x1001, 64)},
        {"RIP": ExprInt((1 << 64) - 1, 64)}, controls=controls, control_masks=masks)
    knownness = knownness_inputs_for_observation(observed)
    assert predict_residual_control(residual, "repeat", state, knownness, 1) == 1
    assert predict_residual_control(residual, "next_ip", state, knownness, 1) == 0x1001
    syscall_pre = predict_syscall_prestate(residual, state, knownness, 1)
    assert syscall_pre.registers["RAX"].value == observed["RAX"]


def test_false_guarded_store_does_not_read_invalid_pointer_or_value():
    effect = IntelOrderedEffect(
        ExprId("RAX", 64), ExprMem(ExprId("RBX", 64), 8),
        ExprInt((1 << 64) - 1, 64), ExprInt(0xff, 8), ExprInt(0, 1),
    )
    residual = IntelInstructionResidual(0x1000, 1, {"RAX": ExprId("RAX", 64)},
        {"RAX": ExprInt((1 << 64) - 1, 64)}, effects=(effect,))
    transform = residual.to_transform(1)
    reads = []

    class State:
        arch = transform.arch
        strict = True
        execution_tid = None
        allocation_bases = ()

        def read_register(self, name):
            if name == "RAX":
                return 0x2000
            if name == "RBX":
                return 0xdead0000
            raise AssertionError(name)

        def read_memory(self, address, size):
            reads.append((address, size))
            raise AssertionError("guard-false store evaluated its value")

    prediction = predict(transform, State(), knownness_inputs={
        "RAX": (1 << 64) - 1, "RBX": (1 << 64) - 1,
    })
    assert prediction.ordered_writes == ()
    assert not reads


def test_lazy_state_captures_permissions_and_memory_only_on_demand():
    memory_reads, permission_reads = [], []
    data = {0x3000: 0xaa, 0x3001: 0xbb}

    def read_memory(address, size):
        memory_reads.append((address, size))
        return bytes(data[address + offset] for offset in range(size))

    def permissions(address, size):
        permission_reads.append((address, size))
        return 11  # mapped, readable, writable

    state = IntelPreBoundaryState(observations(), read_memory, permissions, guest_limit=0x10000)
    assert not memory_reads and not permission_reads
    assert state.read_memory(0x3000, 2) == b"\xaa\xbb"
    assert state.read_memory(0x3000, 2) == b"\xaa\xbb"
    assert memory_reads == [(0x3000, 1), (0x3001, 1)]
    assert permission_reads == [(0x3000, 1), (0x3001, 1)]
    assert state.permission_evidence == {0x3000: (True, True), 0x3001: (True, True)}


def test_source_load_uses_fresh_preboundary_bytes_for_each_assignment():
    residual = IntelInstructionResidual(0x1000, 1,
        {"RCX": ExprMem(ExprId("RBX", 64), 64), "RIP": ExprInt(0x1001, 64)},
        {"RCX": ExprInt((1 << 64) - 1, 64), "RIP": ExprInt((1 << 64) - 1, 64)})
    seen = []
    for address, raw, expected in (
        (0x3000, bytes.fromhex("0102030405060708"), 0x0807060504030201),
        (0x4000, bytes.fromhex("ffeeddccbbaa9988"), 0x8899aabbccddeeff),
    ):
        observed = observations()
        observed.update(RIP=0x1000, RBX=address)
        def read_memory(start, size):
            seen.append((address, start, size))
            return raw[start - address:start - address + size]
        state = IntelPreBoundaryState(observed, read_memory, lambda *_: 9)
        prediction = predict(residual.to_transform(2), state,
            knownness_inputs=knownness_inputs_for_observation(observed),
            register_names=("RCX",))
        assert prediction.registers["RCX"].value == expected
        assert len(state.memory) == 8
    assert {row[0] for row in seen} == {0x3000, 0x4000}


def test_composed_store_then_load_forwards_without_future_memory_capture():
    pc, address = 0x1000, 0x3000
    full64 = ExprInt((1 << 64) - 1, 64)
    first = IntelInstructionResidual(pc, 1,
        {"RIP": ExprInt(pc + 1, 64)}, {"RIP": full64},
        effects=(IntelOrderedEffect(ExprId("RAX", 64), ExprId("RBX", 64),
            full64, full64, ExprInt(1, 1)),))
    second = IntelInstructionResidual(pc + 1, 1,
        {"RCX": ExprMem(ExprId("RAX", 64), 64), "RIP": ExprInt(pc + 2, 64)},
        {"RCX": full64, "RIP": full64})
    observed = observations()
    observed.update(RIP=pc, RAX=address, RBX=0x1122334455667788)
    data_reads = []
    state = IntelPreBoundaryState(observed,
        lambda a, n: data_reads.append((a, n)) or b"\\x00" * n,
        lambda *_: 11)
    transform = compose_intel_residuals((first, second), 3)
    prediction = predict_intel_transform(transform, state,
                                        knownness_inputs_for_observation(observed))
    assert prediction.registers["RCX"].value == 0x1122334455667788
    assert prediction.ordered_writes == ((address, bytes.fromhex("8877665544332211")),)
    assert not data_reads


def test_lazy_state_rejects_nonreadable_memory_before_fetch():
    reads = []
    state = IntelPreBoundaryState(observations(), lambda *args: reads.append(args) or b"x",
                                  lambda *_: 10)
    with pytest.raises(MemoryAccessError, match="read permission"):
        state.read_memory(0x4000, 1)
    assert not reads


def test_importer_rejects_future_or_self_store_prefix_but_accepts_prior_prefix():
    effects = [
        {"kind": "write", "condition": const(0, 1), "address": reg("RAX", 64),
         "address_mask": const((1 << 64) - 1, 64), "bytes": 1,
         "value": const(0, 8), "value_mask": const(255, 8)},
        {"kind": "read", "condition": const(1, 1), "address": memory_after(1, 64),
         "address_mask": const((1 << 64) - 1, 64), "bytes": 1},
        {"kind": "write", "condition": const(1, 1), "address": reg("RAX", 64),
         "address_mask": const((1 << 64) - 1, 64), "bytes": 1,
         "value": memory_after(1), "value_mask": const(255, 8)},
    ]
    digest, document = residual_document(effects=effects,
        outputs={"RIP": memory_after(2, 64)})
    encoded = __import__("json").dumps(document)
    decoded = decode_intel_residual(encoded, pc=0x1000, code=b"\x90", iform="NOP_90",
                                    model_sha256=digest)
    assert len(decoded.effects) == 2
    assert decoded.read_effects[0].write_prefix == 1
    future_read = [effects[0], dict(effects[1], address=memory_after(2, 64))]
    _, malformed_read = residual_document(effects=future_read)
    with pytest.raises(SymbolEvaluationError, match="Invalid Intel source residual"):
        decode_intel_residual(__import__("json").dumps(malformed_read), pc=0x1000,
                              code=b"\x90", iform="NOP_90", model_sha256=digest)
    self_store = [dict(effects[0], value=memory_after(1))]
    _, malformed = residual_document(effects=self_store)
    with pytest.raises(SymbolEvaluationError, match="Invalid Intel source residual"):
        decode_intel_residual(__import__("json").dumps(malformed), pc=0x1000, code=b"\x90",
                              iform="NOP_90", model_sha256=digest)


def test_inactive_write_keeps_prefix_ordinal_without_evaluating_operands():
    effects = [
        {"kind": "write", "condition": const(0, 1), "address": reg("RAX", 64),
         "address_mask": const((1 << 64) - 1, 64), "bytes": 1,
         "value": {"kind": "memory", "bits": 8, "address": reg("RBX", 64)},
         "value_mask": const(255, 8)},
        {"kind": "write", "condition": const(1, 1), "address": reg("RAX", 64),
         "address_mask": const((1 << 64) - 1, 64), "bytes": 1,
         "value": memory_after(1), "value_mask": const(255, 8)},
    ]
    digest, document = residual_document(effects=effects)
    residual = decode_intel_residual(__import__("json").dumps(document), pc=0x1000,
        code=b"\x90", iform="NOP_90", model_sha256=digest)
    reads = []
    state = IntelPreBoundaryState(
        {"RAX": 0x2000, "RBX": 0xdead0000},
        lambda address, size: reads.append((address, size)) or b"\x7a",
        lambda *_: 11,
    )
    transform = residual.to_transform(1)
    prediction = predict(transform, state, knownness_inputs={
        "RAX": (1 << 64) - 1, "RBX": (1 << 64) - 1,
    })
    assert prediction.ordered_writes == ((0x2000, b"\x7a"),)
    assert reads == [(0x2000, 1)]


def test_symbolic_live_model_uses_source_residual_and_shared_boundary_compare():
    observed = observations()
    observed["RIP"] = 0x1000
    instruction = SimpleNamespace(pc=0x1000, code=b"\x90", iform="NOP_90",
                                  next_pc=0x1001)
    residual = IntelInstructionResidual(0x1000, 1, {"RIP": ExprInt(0x1001, 64)},
        {"RIP": ExprInt((1 << 64) - 1, 64)}, controls={
            "next_ip": ExprInt(0x1001, 64), "repeat": ExprInt(0, 1),
            "environment_cutpoint": ExprInt(0, 1),
        }, control_masks={
            "next_ip": ExprInt((1 << 64) - 1, 64), "repeat": ExprInt(1, 1),
            "environment_cutpoint": ExprInt(1, 1),
        })
    class Backend:
        def specialize(self, _):
            return residual
    class Decoder:
        def decode(self, _pc, _code):
            return instruction
    class Transport:
        def read_memory(self, _address, size):
            return b"\x90" * size
        def memory_permissions(self, _address, _size):
            return 13
    model = SymbolicIntelLiveModel(Backend(), Decoder(), Transport(), 123)
    model.boundary(observed)
    prediction = model.predict(SimpleNamespace(pc=0x1000, address=0x1000, size=1))
    actual = normalize_observed_registers(observed)
    actual["RIP"] = 0x1001
    result = compare_intel_boundary(prediction, actual, {}, set(), require_store_coverage=True)
    assert result.ok
    assert model.next_ip is None  # Next_IP is an environment/syscall obligation only.
    assert not model.environment_cutpoint


def test_guarded_read_effect_is_lazy_and_permission_checked():
    observed = observations()
    reads = []
    state = IntelPreBoundaryState(observed,
        lambda address, size: reads.append((address, size)) or b"\xaa" * size,
        lambda *_: 9)
    knownness = knownness_inputs_for_observation(observed)
    common = dict(address=ExprId("RAX", 64),
        address_mask=ExprInt((1 << 64) - 1, 64), byte_count=2, write_prefix=0)
    false_read = IntelInstructionResidual(0x1000, 1,
        {"RIP": ExprInt(0x1001, 64)}, {"RIP": ExprInt((1 << 64) - 1, 64)},
        read_effects=(IntelReadEffect(condition=ExprInt(0, 1), **common),))
    prefix = SymbolicTransformComposer(SymbolicTransform(
        5, {}, [], state.arch, 0x1000, 0x1000, defined_masks={}, source_owned=True))
    records = project_intel_read_effects(false_read, 5, prefix_composer=prefix)
    false_transform = false_read.to_transform(5)
    predict_intel_transform(false_transform, state, knownness)
    capture_projected_intel_read_effects(false_transform, records, state, knownness)
    assert not reads
    active_read = IntelInstructionResidual(0x1000, 1,
        {"RIP": ExprInt(0x1001, 64)}, {"RIP": ExprInt((1 << 64) - 1, 64)},
        read_effects=(IntelReadEffect(condition=ExprInt(1, 1), **common),))
    active_transform = active_read.to_transform(5)
    records = project_intel_read_effects(active_read, 5, prefix_composer=prefix)
    predict_intel_transform(active_transform, state, knownness)
    capture_projected_intel_read_effects(active_transform, records, state, knownness)
    assert reads == [(observed["RAX"], 1), (observed["RAX"] + 1, 1)]
    assert state.memory == {observed["RAX"]: 0xaa, observed["RAX"] + 1: 0xaa}


def test_taken_branch_uses_architectural_rip_not_environment_next_ip():
    pc, target = 0x1000, 0x2000
    residual = IntelInstructionResidual(pc, 1, {"RIP": ExprInt(target, 64)},
        {"RIP": ExprInt((1 << 64) - 1, 64)}, controls={
            "next_ip": ExprInt(pc + 1, 64), "repeat": ExprInt(0, 1),
            "environment_cutpoint": ExprInt(0, 1),
        }, control_masks={
            "next_ip": ExprInt((1 << 64) - 1, 64), "repeat": ExprInt(1, 1),
            "environment_cutpoint": ExprInt(1, 1),
        })
    observed = observations()
    observed["RIP"] = pc
    class Backend:
        def specialize(self, _):
            return residual
    class Decoder:
        def decode(self, _pc, _code):
            return SimpleNamespace(pc=pc, code=b"\x90", iform="JMP_RELBRb")
    class Transport:
        def read_memory(self, _address, size):
            return b"\x90" * size
        def memory_permissions(self, _address, _size):
            return 13
    model = SymbolicIntelLiveModel(Backend(), Decoder(), Transport(), 21)
    model.boundary(observed)
    prediction = model.predict(SimpleNamespace(pc=pc, address=pc, size=1))
    assert prediction.registers["RIP"].value == target
    assert model.next_ip is None


def test_taken_branch_inside_observed_tb_is_rejected():
    pc = 0x1000
    residual = IntelInstructionResidual(pc, 1, {"RIP": ExprInt(0x2000, 64)},
        {"RIP": ExprInt((1 << 64) - 1, 64)}, controls={
            "next_ip": ExprInt(pc + 1, 64), "repeat": ExprInt(0, 1),
            "environment_cutpoint": ExprInt(0, 1),
        }, control_masks={
            "next_ip": ExprInt((1 << 64) - 1, 64), "repeat": ExprInt(1, 1),
            "environment_cutpoint": ExprInt(1, 1),
        })
    observed = observations()
    observed["RIP"] = pc
    class Backend:
        def specialize(self, _):
            return residual
    class Decoder:
        def decode(self, address, _code):
            return SimpleNamespace(pc=address, code=b"\x90", iform="JMP_RELBRb")
    class Transport:
        def read_memory(self, _address, size):
            return b"\x90" * size
        def memory_permissions(self, _address, _size):
            return 13
    model = SymbolicIntelLiveModel(Backend(), Decoder(), Transport(), 22)
    model.boundary(observed)
    with pytest.raises(SymbolEvaluationError, match="control transfer inside"):
        model.predict(SimpleNamespace(pc=pc, address=pc + 1, size=2))


def test_read_effect_condition_uses_composed_prefix_without_fake_write():
    pc = 0x1001
    rcx = ExprId("RCX", 64)
    condition = ExprCond(ExprOp("==", rcx, ExprInt(0, 64)), ExprInt(0, 1),
        ExprCond(ExprOp("==", rcx, ExprInt(1, 64)), ExprInt(0, 1), ExprInt(1, 1)))
    observed = observations()
    observed.update(RIP=0x1000, RCX=1, RDI=0x3000)
    reads = []
    state = IntelPreBoundaryState(observed,
        lambda address, size: reads.append((address, size)) or b"\\xaa" * size,
        lambda *_: 9)
    knownness = knownness_inputs_for_observation(observed)
    prior = SymbolicTransform(1, {ExprId("RCX", 64): ExprInt(0, 64)}, [], state.arch,
        0x1000, pc, defined_masks={"RCX": ExprInt((1 << 64) - 1, 64)}, source_owned=True)
    residual = IntelInstructionResidual(pc, 1, {"RIP": ExprInt(pc + 1, 64)},
        {"RIP": ExprInt((1 << 64) - 1, 64)}, read_effects=(IntelReadEffect(
            ExprId("RDI", 64), ExprInt((1 << 64) - 1, 64), 1, condition, 0),))
    prefix = SymbolicTransformComposer(prior)
    records = project_intel_read_effects(residual, 1, prefix_composer=prefix)
    whole = prefix.fork()
    whole.append(residual.to_transform(1))
    transform = whole.finish()
    predict_intel_transform(transform, state, knownness)
    capture_projected_intel_read_effects(transform, records, state, knownness)
    assert reads == []  # incoming RCX was nonzero, but the composed state cleared it
    assert not state.memory


def test_literal_control_fastpath_does_not_drop_source_guards():
    pc = 0x1000
    residual = IntelInstructionResidual(pc, 1,
        {"RIP": ExprInt(pc + 1, 64)},
        {"RIP": ExprInt((1 << 64) - 1, 64)}, guards=(ExprInt(0, 1),),
        controls={"next_ip": ExprInt(pc + 1, 64), "repeat": ExprInt(0, 1),
                  "environment_cutpoint": ExprInt(0, 1)},
        control_masks={"next_ip": ExprInt((1 << 64) - 1, 64), "repeat": ExprInt(1, 1),
                       "environment_cutpoint": ExprInt(1, 1)},
    )
    observed = observations()
    observed["RIP"] = pc
    class Backend:
        def specialize(self, _):
            return residual
    class Decoder:
        def decode(self, _pc, _code):
            return SimpleNamespace(pc=pc, code=b"\x90", iform="NOP_90")
    class Transport:
        def read_memory(self, _address, size):
            return b"\x90" * size
        def memory_permissions(self, _address, _size):
            return 13
    model = SymbolicIntelLiveModel(Backend(), Decoder(), Transport(), 25)
    model.boundary(observed)
    with pytest.raises(SymbolEvaluationError, match="Source runtime guard 0 is false"):
        model.predict(SimpleNamespace(pc=pc, address=pc, size=1))


def test_symbolic_rep_composes_source_strides_without_guest_callbacks():
    pc = 0x1000
    rcx, rdi = ExprId("RCX", 64), ExprId("RDI", 64)
    repeat = ExprCond(ExprOp("==", rcx, ExprInt(0, 64)), ExprInt(0, 1),
                      ExprCond(ExprOp("==", rcx, ExprInt(1, 64)), ExprInt(0, 1), ExprInt(1, 1)))
    source_rip = ExprCond(repeat, ExprInt(pc, 64), ExprInt(pc + 2, 64))
    next_ip = ExprInt(pc + 2, 64)  # environment Next_IP remains fallthrough
    residual = IntelInstructionResidual(pc, 2,
        {"RCX": rcx - ExprInt(1, 64), "RDI": rdi + ExprInt(1, 64), "RIP": source_rip},
        {"RCX": ExprInt((1 << 64) - 1, 64), "RDI": ExprInt((1 << 64) - 1, 64),
         "RIP": ExprInt((1 << 64) - 1, 64)},
        effects=(IntelOrderedEffect(rdi, ExprInt(0x5a, 8), ExprInt((1 << 64) - 1, 64),
                                    ExprInt(0xff, 8), ExprInt(1, 1)),),
        controls={"next_ip": next_ip, "repeat": repeat, "environment_cutpoint": ExprInt(0, 1)},
        control_masks={"next_ip": ExprInt((1 << 64) - 1, 64), "repeat": ExprInt(1, 1),
                       "environment_cutpoint": ExprInt(1, 1)},
    )
    observed = observations()
    observed.update(RIP=pc, RCX=2, RDI=0x3000)
    class Backend:
        def specialize(self, _):
            return residual
    class Decoder:
        def decode(self, _pc, _code):
            return SimpleNamespace(pc=pc, code=bytes.fromhex("f3aa"), iform="REP_STOSB")
    class Transport:
        def read_memory(self, _address, size):
            return bytes.fromhex("f3aa")[:size]
        def memory_permissions(self, _address, _size):
            return 15
    model = SymbolicIntelLiveModel(Backend(), Decoder(), Transport(), 12)
    model.boundary(observed)
    prediction = model.predict(SimpleNamespace(pc=pc, address=pc, size=1))
    assert model.instructions == 2
    assert model.decoded[0]["source_iterations"] == 2
    assert prediction.registers["RCX"].value == 0
    assert prediction.registers["RDI"].value == 0x3002
    assert prediction.registers["RIP"].value == pc + 2
    assert prediction.ordered_writes == ((0x3000, b"\x5a"), (0x3001, b"\x5a"))


def test_symbolic_backend_requests_exact_xed_binding_and_caches():
    digest, document = residual_document()
    class Oracle:
        requests = []
        def checked(self, request):
            self.requests.append(request)
            return {"result": document}
    instruction = SimpleNamespace(pc=0x1000, code=b"\x90", iform="NOP_90",
        operand_size=32, address_size=64, fields=(("rexw", 0), ("mod", 3)))
    oracle = Oracle()
    backend = IntelSymbolicBackend(oracle, digest)
    first = backend.specialize(instruction)
    second = backend.specialize(instruction)
    assert first is second
    assert backend.requests == 1
    assert oracle.requests[0] == {
        "op": "symbolic_instruction", "profile": PROFILE, "pc": "4096",
        "code": "90", "iform": "NOP_90", "operand_size": 32,
        "address_size": 64, "fields": {"rexw": 0, "mod": 3},
    }


def test_rep_count_zero_does_not_resolve_guarded_invalid_memory():
    pc = 0x1000
    residual = IntelInstructionResidual(pc, 2,
        {"RIP": ExprInt(pc + 2, 64), "RCX": ExprId("RCX", 64)},
        {"RIP": ExprInt((1 << 64) - 1, 64), "RCX": ExprInt((1 << 64) - 1, 64)},
        effects=(IntelOrderedEffect(ExprId("RBX", 64), ExprMem(ExprId("R15", 64), 8),
            ExprInt((1 << 64) - 1, 64), ExprInt(0xff, 8), ExprInt(0, 1)),),
        controls={"next_ip": ExprInt(pc + 2, 64), "repeat": ExprInt(0, 1),
                  "environment_cutpoint": ExprInt(0, 1)},
        control_masks={"next_ip": ExprInt((1 << 64) - 1, 64), "repeat": ExprInt(1, 1),
                       "environment_cutpoint": ExprInt(1, 1)},
        read_effects=(IntelReadEffect(ExprId("R15", 64), ExprInt((1 << 64) - 1, 64),
                                      8, ExprInt(0, 1), 0),),
    )
    observed = observations()
    observed.update(RIP=pc, RCX=0, RBX=0xdead0000, R15=0xffff_ffff_ffff)
    forbidden = []
    class Backend:
        def specialize(self, _):
            return residual
    class Decoder:
        def decode(self, _pc, _code):
            return SimpleNamespace(pc=pc, code=bytes.fromhex("f3aa"), iform="REP_STOSB")
    class Transport:
        def read_memory(self, address, size):
            if address >= 0xdead0000:
                forbidden.append((address, size))
                raise AssertionError("count-zero source path read invalid guest memory")
            return bytes.fromhex("f3aa")[:size]
        def memory_permissions(self, address, _size):
            if address >= 0xdead0000:
                forbidden.append((address, 0))
                return 0
            return 15
    model = SymbolicIntelLiveModel(Backend(), Decoder(), Transport(), 13)
    model.boundary(observed)
    prediction = model.predict(SimpleNamespace(pc=pc, address=pc, size=1))
    assert model.instructions == 1
    assert prediction.ordered_writes == ()
    assert not prediction.memory and not forbidden


def test_importer_accepts_synthetic_knownness_only_in_masks():
    digest, document = residual_document(outputs={
        "RAX": reg("RAX", 64), "RIP": const(0x1001, 64),
        "XMM0": reg("XMM0", 128),
    })
    document["defined_masks"] = {
        "RAX": reg("__focaccia_known_RAX", 64),
        "RIP": const((1 << 64) - 1, 64),
        "XMM0": {"kind": "slice", "bits": 128, "start": 0,
            "value": {"kind": "binary", "bits": 512, "op": "and",
                "left": reg("__focaccia_known_ZMM0", 512),
                "right": const((1 << 128) - 1, 512)}},
    }
    residual = decode_intel_residual(__import__("json").dumps(document), pc=0x1000,
        code=b"\x90", iform="NOP_90", model_sha256=digest)
    observed = observations()
    state = IntelPreBoundaryState(observed, lambda *_: b"", lambda *_: 11)
    prediction = predict_intel_transform(residual.to_transform(1), state,
                                        knownness_inputs_for_observation(observed))
    assert prediction.registers["RAX"].mask == (1 << 64) - 1
    assert prediction.registers["XMM0"].mask == (1 << 128) - 1
    document["outputs"]["RAX"] = reg("__focaccia_known_RAX", 64)
    with pytest.raises(SymbolEvaluationError, match="Invalid Intel source residual"):
        decode_intel_residual(__import__("json").dumps(document), pc=0x1000,
                              code=b"\x90", iform="NOP_90", model_sha256=digest)


def test_importer_allows_omitted_non_syscall_prestate_fields():
    digest, document = residual_document()
    document.pop("syscall_pre")
    document.pop("syscall_pre_masks")
    residual = decode_intel_residual(__import__("json").dumps(document), pc=0x1000,
        code=b"\x90", iform="NOP_90", model_sha256=digest)
    assert not any(name.startswith("syscall_pre.") for name in residual.controls)


def test_residual_dag_cache_revalidates_knownness_register_use_by_field():
    digest, document = residual_document(outputs={
        "RAX": reg("RAX", 64), "RIP": const(0x1001, 64),
    })
    document["definitions"] = [{"id": 0, **reg("__focaccia_known_RAX", 64)}]
    document["defined_masks"] = {
        "RAX": {"kind": "reference", "bits": 64, "id": 0},
        "RIP": const((1 << 64) - 1, 64),
    }
    decoded = decode_intel_residual(__import__("json").dumps(document), pc=0x1000,
        code=b"\x90", iform="NOP_90", model_sha256=digest)
    assert decoded.defined_masks["RAX"].name == "__focaccia_known_RAX"
    document["outputs"]["RAX"] = {"kind": "reference", "bits": 64, "id": 0}
    with pytest.raises(SymbolEvaluationError, match="Unsupported architectural input register through"):
        decode_intel_residual(__import__("json").dumps(document), pc=0x1000,
            code=b"\x90", iform="NOP_90", model_sha256=digest)


def test_residual_dag_cache_revalidates_memory_prefix_at_write_use():
    digest, document = residual_document(effects=[])
    document["definitions"] = [{"id": 0, **memory_after(1, 64)}]
    document["ordered_effects"] = [{
        "kind": "write", "condition": const(1, 1),
        "address": {"kind": "reference", "bits": 64, "id": 0},
        "address_mask": const((1 << 64) - 1, 64), "bytes": 1,
        "value": const(0, 8), "value_mask": const(255, 8),
    }]
    with pytest.raises(SymbolEvaluationError, match="prefix through expression reference"):
        decode_intel_residual(__import__("json").dumps(document), pc=0x1000,
            code=b"\x90", iform="NOP_90", model_sha256=digest)


def test_importer_binds_instruction_and_model_identity():
    digest, document = residual_document()
    encoded = __import__("json").dumps(document)
    with pytest.raises(SymbolEvaluationError, match="identity/profile"):
        decode_intel_residual(encoded, pc=0x1001, code=b"\x90", iform="NOP_90",
                              model_sha256=digest)
    with pytest.raises(SymbolEvaluationError, match="identity/profile"):
        decode_intel_residual(encoded, pc=0x1000, code=b"\x90", iform="NOP_90",
                              model_sha256="b" * 64)
