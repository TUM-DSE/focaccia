import pytest

from focaccia.arch.aarch64 import ArchAArch64
from focaccia.arch.x86 import ArchX86
from focaccia.native.spec_syscalls import NativeLinuxPolicy
from focaccia.native.spec_validate import (
    NativeSnapshot,
    NativeStep,
    SpecValidationError,
    UnsupportedNativeEvent,
)

CAPABILITY = "full-private-memory-boundary-diff"
PATH = b"/qualified/input"


def snapshot(arch, registers, memory=None, mappings=None, stdout=b"", stderr=b""):
    return NativeSnapshot(
        arch,
        registers,
        memory or {},
        (
            ({"start": 0x1000, "end": 0x10000, "perms": "rw-", "private": True},)
            if mappings is None
            else mappings
        ),
        CAPABILITY,
        stdout,
        stderr,
    )


def syscall(arch, number, args, pc=0x1000, extra=None):
    if arch.archname == "aarch64":
        registers = {"PC": pc, "X8": number, **{f"X{i}": value for i, value in enumerate(args)}}
    else:
        registers = {
            "RIP": pc,
            "RAX": number,
            **dict(zip(("RDI", "RSI", "RDX", "R10", "R8", "R9"), args)),
        }
    registers.update(extra or {})
    return registers


def successor(
    pre, result, *, pcinc=None, changed=None, memory=None, mappings=None, stdout=None, stderr=None
):
    arm = "PC" in pre.registers
    registers = dict(pre.registers)
    pc = "PC" if arm else "RIP"
    registers[pc] += pcinc if pcinc is not None else (4 if arm else 2)
    registers["X0" if arm else "RAX"] = result
    registers.update(changed or {})
    return NativeSnapshot(
        pre.arch,
        registers,
        pre.memory if memory is None else memory,
        pre.mappings if mappings is None else mappings,
        CAPABILITY,
        pre.stdout if stdout is None else stdout,
        pre.stderr if stderr is None else stderr,
    )


def test_syscall_preservation_resume_and_arm_x8():
    for arch, number, args, extra in (
        (ArchX86(), 1, (1, 0x2000, 1, 0, 0, 0), {"RBX": 7}),
        (ArchAArch64("little"), 64, (1, 0x2000, 1, 0, 0, 0), {"X19": 9}),
    ):
        pre = snapshot(arch, syscall(arch, number, args, extra=extra), {0x2000: b"x"})
        token = NativeLinuxPolicy().preflight(pre)
        assert token.op == "write"
        stream = {"stdout": b"x"} if args[0] == 1 else {"stderr": b"x"}
        NativeLinuxPolicy().validate(
            pre, successor(pre, 1, **stream), NativeStep("instruction"), token
        )
        changed = {"X19": 0} if arch.archname == "aarch64" else {"RBX": 0}
        with pytest.raises(SpecValidationError, match="preserved register"):
            NativeLinuxPolicy().validate(
                pre, successor(pre, 1, changed=changed, **stream), NativeStep("instruction"), token
            )
        with pytest.raises(SpecValidationError, match="resume PC"):
            NativeLinuxPolicy().validate(
                pre, successor(pre, 1, pcinc=8, **stream), NativeStep("instruction"), token
            )


def test_aarch64_syscall_preserves_nzcv_but_ignores_debugger_ss_bit():
    arch = ArchAArch64("little")
    pre = snapshot(arch, syscall(arch, 96, (0, 0, 0, 0, 0, 0), extra={"CPSR": 0x60201000}))
    policy = NativeLinuxPolicy()
    token = policy.preflight(pre)
    after = successor(pre, 123, changed={"CPSR": 0x60001000})
    policy.validate(pre, after, NativeStep("instruction"), token)
    changed_nzcv = successor(pre, 123, changed={"CPSR": 0x70001000})
    with pytest.raises(SpecValidationError, match="CPSR.NZCV"):
        policy.validate(pre, changed_nzcv, NativeStep("instruction"), token)


def test_missing_syscall_argument_is_not_defaulted():
    pre = snapshot(ArchX86(), {"RIP": 0x1000, "RAX": 1, "RDI": 1, "RSI": 0x2000})
    with pytest.raises(UnsupportedNativeEvent, match="omitted required"):
        NativeLinuxPolicy().preflight(pre)


@pytest.mark.parametrize(
    "arch,nr,args,pcinc",
    [
        (ArchAArch64("little"), 63, (0, 0x2000, 4, 0, 0, 0), 4),
        (ArchX86(), 0, (0, 0x2000, 4, 0, 0, 0), 2),
    ],
)
def test_stdin_partial_and_errno_reads(arch, nr, args, pcinc):
    pre = snapshot(arch, syscall(arch, nr, args), {0x2000: b"...."})
    policy = NativeLinuxPolicy(stdin=b"abcd")
    token = policy.preflight(pre)
    policy.validate(
        pre,
        successor(pre, 2, pcinc=pcinc, memory={0x2000: b"ab.."}),
        NativeStep("instruction"),
        token,
    )
    token = policy.preflight(pre)
    policy.validate(
        pre,
        successor(pre, (-11) & ((1 << 64) - 1), pcinc=pcinc),
        NativeStep("instruction"),
        token,
    )
    bad = successor(pre, 2, pcinc=pcinc, memory={0x2000: b"zz.."})
    with pytest.raises(SpecValidationError, match="read buffer"):
        NativeLinuxPolicy(stdin=b"abcd").validate(pre, bad, NativeStep("instruction"), token)


def test_readonly_paths_are_explicit_and_write_create_flags_rejected():
    arch = ArchX86()
    memory = {0x2000: PATH + b"\0"}
    for flags in (1, 0x40, 0x241):
        pre = snapshot(arch, syscall(arch, 2, (0x2000, flags, 0, 0, 0, 0)), memory)
        with pytest.raises(UnsupportedNativeEvent, match="readonly"):
            NativeLinuxPolicy(allowed_read_paths=(PATH,)).preflight(pre)
    pre = snapshot(arch, syscall(arch, 2, (0x2000, 0, 0, 0, 0, 0)), memory)
    with pytest.raises(UnsupportedNativeEvent, match="qualified"):
        NativeLinuxPolicy().preflight(pre)


@pytest.mark.parametrize(
    "arch,open_nr,read_nr,fstat_nr,close_nr,pcinc",
    [
        (ArchX86(), 257, 0, 5, 3, 2),
        (ArchAArch64("little"), 56, 63, 80, 57, 4),
    ],
)
def test_openat_read_fstat_close_chain_both_abis(arch, open_nr, read_nr, fstat_nr, close_nr, pcinc):
    stat_size = 144 if arch.archname == "x86_64" else 128
    memory = {0x2000: PATH + b"\0", 0x3000: b"." * 4, 0x4000: b"\0" * stat_size}
    policy = NativeLinuxPolicy(allowed_read_paths=(PATH,))

    pre = snapshot(arch, syscall(arch, open_nr, (-100, 0x2000, 0, 0, 0, 0)), memory)
    token = policy.preflight(pre)
    policy.validate(pre, successor(pre, 3, pcinc=pcinc), NativeStep("instruction"), token)
    with pytest.raises(UnsupportedNativeEvent, match="readonly descriptor"):
        policy.preflight(snapshot(arch, syscall(arch, read_nr, (1, 0x3000, 4, 0, 0, 0)), memory))

    read_args = (3, 0x3000, 4, 0, 0, 0)
    fstat_args = (3, 0x4000, 0, 0, 0, 0)
    close_args = (3, 0, 0, 0, 0, 0)
    pre = snapshot(arch, syscall(arch, read_nr, read_args, pc=0x1000 + pcinc), memory)
    token = policy.preflight(pre)
    policy.validate(
        pre,
        successor(pre, 4, pcinc=pcinc, memory={**memory, 0x3000: b"data"}),
        NativeStep("instruction"),
        token,
    )
    pre = snapshot(arch, syscall(arch, fstat_nr, fstat_args, pc=0x1000 + 2 * pcinc), memory)
    token = policy.preflight(pre)
    policy.validate(pre, successor(pre, 0, pcinc=pcinc), NativeStep("instruction"), token)
    pre = snapshot(arch, syscall(arch, close_nr, close_args, pc=0x1000 + 3 * pcinc), memory)
    token = policy.preflight(pre)
    policy.validate(pre, successor(pre, 0, pcinc=pcinc), NativeStep("instruction"), token)
    assert 3 not in policy.owned_fds
    with pytest.raises(UnsupportedNativeEvent, match="policy-owned"):
        policy.preflight(snapshot(arch, syscall(arch, read_nr, read_args), memory))


def test_legacy_stat_uses_qualified_path_and_x86_64_layout():
    arch = ArchX86()
    stat_bytes = b"\0" * 144
    memory = {0x2000: PATH + b"\0", 0x3000: stat_bytes}
    pre = snapshot(arch, syscall(arch, 4, (0x2000, 0x3000, 0, 0, 0, 0)), memory)
    policy = NativeLinuxPolicy(allowed_read_paths=(PATH,))
    token = policy.preflight(pre)
    policy.validate(pre, successor(pre, 0), NativeStep("instruction"), token)
    assert token.op == "stat"
    with pytest.raises(UnsupportedNativeEvent, match="qualified"):
        NativeLinuxPolicy().preflight(pre)


def test_robust_list_uses_architecture_size_argument():
    for arch, nr, pointer in (
        (ArchX86(), 273, 0x2000),
        (ArchAArch64("little"), 99, 0x2000),
    ):
        args = [0] * 6
        args[0], args[1] = pointer, 24
        pre = snapshot(arch, syscall(arch, nr, tuple(args)), {pointer: b"\0" * 24})
        assert NativeLinuxPolicy().preflight(pre).op == "set_robust_list"
        args[1] = 8
        with pytest.raises(UnsupportedNativeEvent, match="robust-list"):
            NativeLinuxPolicy().preflight(
                snapshot(arch, syscall(arch, nr, tuple(args)), {pointer: b"\0" * 24})
            )


def test_brk_zero_discovers_baseline_without_heap_then_grows():
    arch = ArchX86()
    policy = NativeLinuxPolicy()
    pre = snapshot(arch, syscall(arch, 12, (0, 0, 0, 0, 0, 0)), {}, ())
    token = policy.preflight(pre)
    policy.validate(pre, successor(pre, 0x6000), NativeStep("instruction"), token)
    grown = {"start": 0x5000, "end": 0x7000, "perms": "rw-", "private": True, "name": "[heap]"}
    post_memory = {0x6000: b"\0" * 0x1000}
    req = snapshot(arch, syscall(arch, 12, (0x7000, 0, 0, 0, 0, 0), pc=0x1002), {}, (grown,))
    token = policy.preflight(req)
    policy.validate(
        req,
        successor(req, 0x7000, memory=post_memory, mappings=(grown,)),
        NativeStep("instruction"),
        token,
    )
    outside = snapshot(arch, syscall(arch, 12, (0x5000000000, 0, 0, 0, 0, 0)), {}, (grown,))
    with pytest.raises(UnsupportedNativeEvent, match="bounded"):
        policy.preflight(outside)


def test_exit_allows_none_post_snapshot():
    arch = ArchX86()
    pre = snapshot(arch, syscall(arch, 231, (0, 0, 0, 0, 0, 0)))
    token = NativeLinuxPolicy().preflight(pre)
    NativeLinuxPolicy().validate(pre, None, NativeStep("exit", 0), token)


def test_negative_errno_does_not_mutate_state_and_munmap_accepts_removed_bytes():
    arch = ArchX86()
    policy = NativeLinuxPolicy(allowed_read_paths=(PATH,))
    path = PATH + b"\0"
    open_pre = snapshot(arch, syscall(arch, 257, (-100, 0x2000, 0, 0, 0, 0)), {0x2000: path})
    token = policy.preflight(open_pre)
    policy.validate(open_pre, successor(open_pre, 3), NativeStep("instruction"), token)
    bad_read = snapshot(arch, syscall(arch, 0, (3, 0x3000, 4, 0, 0, 0)), {0x3000: b"...."})
    token = policy.preflight(bad_read)
    policy.validate(
        bad_read, successor(bad_read, (-5) & ((1 << 64) - 1)), NativeStep("instruction"), token
    )
    assert policy.fd_offsets[3] == 0

    mapped = {"start": 0x5000, "end": 0x6000, "perms": "rw-", "private": True}
    mmap_pre = snapshot(arch, syscall(arch, 9, (0, 4096, 3, 0x22, (1 << 64) - 1, 0)), {}, ())
    token = policy.preflight(mmap_pre)
    policy.validate(
        mmap_pre,
        successor(mmap_pre, 0x5000, memory={0x5000: b"\0" * 4096}, mappings=(mapped,)),
        NativeStep("instruction"),
        token,
    )
    unmap_pre = snapshot(
        arch, syscall(arch, 11, (0x5000, 4096, 0, 0, 0, 0)), {0x5000: b"x" * 4096}, (mapped,)
    )
    token = policy.preflight(unmap_pre)
    policy.validate(
        unmap_pre,
        successor(unmap_pre, 0, memory={}, mappings=()),
        NativeStep("instruction"),
        token,
    )


def test_intel_sha_auxiliary_syscalls_are_bounded_to_current_process():
    arch = ArchX86()
    policy = NativeLinuxPolicy(uid=1000, gid=1001)
    for number, value in ((102, 1000), (104, 1001)):
        pre = snapshot(arch, syscall(arch, number, (0, 0, 0, 0, 0, 0)))
        token = policy.preflight(pre)
        policy.validate(pre, successor(pre, value), NativeStep("instruction"), token)
    for number, value in ((105, 1000), (106, 1001)):
        pre = snapshot(arch, syscall(arch, number, (value, 0, 0, 0, 0, 0)))
        token = policy.preflight(pre)
        policy.validate(pre, successor(pre, 0), NativeStep("instruction"), token)
        bad = snapshot(arch, syscall(arch, number, (value + 1, 0, 0, 0, 0, 0)))
        with pytest.raises(UnsupportedNativeEvent, match="current identity"):
            policy.preflight(bad)

    pre = snapshot(
        arch,
        syscall(arch, 158, (0x1002, 0x7000, 0, 0, 0, 0), extra={"FS_BASE": 0x5000}),
    )
    token = policy.preflight(pre)
    policy.validate(
        pre,
        successor(pre, 0, changed={"FS_BASE": 0x7000}),
        NativeStep("instruction"),
        token,
    )
    error_pre = snapshot(
        arch,
        syscall(arch, 158, (0x1002, 0x7000, 0, 0, 0, 0), extra={"FS_BASE": 0x5000}),
    )
    token = policy.preflight(error_pre)
    with pytest.raises(SpecValidationError, match="preserved register FS_BASE"):
        policy.validate(
            error_pre,
            successor(error_pre, (-1) & ((1 << 64) - 1), changed={"FS_BASE": 0x7000}),
            NativeStep("instruction"),
            token,
        )


def test_nonmapping_syscall_cannot_change_memory_permissions():
    arch = ArchX86()
    policy = NativeLinuxPolicy(uid=1000)
    pre = snapshot(arch, syscall(arch, 102, (0, 0, 0, 0, 0, 0)))
    token = policy.preflight(pre)
    changed_mapping = ({"start": 0x1000, "end": 0x10000, "perms": "r--", "private": True},)
    with pytest.raises(SpecValidationError, match="unauthorized mapping"):
        policy.validate(
            pre,
            successor(pre, 1000, mappings=changed_mapping),
            NativeStep("instruction"),
            token,
        )


def _brk_owned_heap_policy():
    arch = ArchX86()
    policy = NativeLinuxPolicy()
    discover = snapshot(arch, syscall(arch, 12, (0, 0, 0, 0, 0, 0)), {}, ())
    token = policy.preflight(discover)
    policy.validate(discover, successor(discover, 0x5000), NativeStep("instruction"), token)
    heap = {"start": 0x5000, "end": 0x6000, "perms": "rw-", "private": True, "name": "[heap]"}
    grow = snapshot(arch, syscall(arch, 12, (0x6000, 0, 0, 0, 0, 0)), {}, ())
    token = policy.preflight(grow)
    policy.validate(
        grow,
        successor(grow, 0x6000, memory={0x5000: b"\0" * 4096}, mappings=(heap,)),
        NativeStep("instruction"),
        token,
    )
    return arch, policy, heap


def test_map_fixed_replaces_only_zeroed_owned_fresh_heap_page():
    arch, policy, heap = _brk_owned_heap_policy()
    mapping = {**heap, "perms": "---"}
    pre = snapshot(
        arch,
        syscall(arch, 9, (0x5000, 4096, 0, 0x32, (1 << 64) - 1, 0)),
        {0x5000: b"\0" * 4096},
        (heap,),
    )
    token = policy.preflight(pre)
    policy.validate(
        pre,
        successor(pre, 0x5000, memory={}, mappings=(mapping,)),
        NativeStep("instruction"),
        token,
    )


def test_map_fixed_rejects_unowned_nonzero_and_outside_heap_pages():
    arch, policy, heap = _brk_owned_heap_policy()
    args = (0x5000, 4096, 0, 0x32, (1 << 64) - 1, 0)
    nonzero = snapshot(arch, syscall(arch, 9, args), {0x5000: b"x" * 4096}, (heap,))
    with pytest.raises(UnsupportedNativeEvent, match="zero-filled"):
        policy.preflight(nonzero)
    outside_heap = {**heap, "end": 0x7000}
    outside = snapshot(
        arch,
        syscall(arch, 9, (0x6000, 4096, 0, 0x32, (1 << 64) - 1, 0)),
        {0x6000: b"\0" * 4096},
        (outside_heap,),
    )
    with pytest.raises(UnsupportedNativeEvent, match="recently grown"):
        policy.preflight(outside)
    unowned_policy = NativeLinuxPolicy()
    unowned = snapshot(arch, syscall(arch, 9, args), {0x5000: b"\0" * 4096}, (heap,))
    with pytest.raises(UnsupportedNativeEvent, match="recently grown"):
        unowned_policy.preflight(unowned)

    grown_heap = {**heap, "end": 0x7000}
    grow_again = snapshot(
        arch, syscall(arch, 12, (0x7000, 0, 0, 0, 0, 0)), {0x5000: b"\0" * 4096}, (heap,)
    )
    token = policy.preflight(grow_again)
    policy.validate(
        grow_again,
        successor(
            grow_again,
            0x7000,
            memory={0x5000: b"\0" * 4096, 0x6000: b"\0" * 4096},
            mappings=(grown_heap,),
        ),
        NativeStep("instruction"),
        token,
    )
    stale_page = snapshot(arch, syscall(arch, 9, args), {0x5000: b"\0" * 4096}, (heap,))
    with pytest.raises(UnsupportedNativeEvent, match="recently grown"):
        policy.preflight(stale_page)


def test_mprotect_rejects_readability_changes_before_execution():
    arch = ArchX86()
    policy = NativeLinuxPolicy()
    policy.mmaps[0x5000] = 4096
    mapping = {"start": 0x5000, "end": 0x6000, "perms": "rw-", "private": True}
    pre = snapshot(arch, syscall(arch, 10, (0x5000, 4096, 0, 0, 0, 0)), {}, (mapping,))
    with pytest.raises(UnsupportedNativeEvent, match="readability changes"):
        policy.preflight(pre)


def test_malformed_mapping_ranges_rejected_during_preflight():
    arch = ArchX86()
    malformed = {"start": 0x6000, "end": 0x5000, "perms": "rw-", "private": True}
    pre = snapshot(arch, syscall(arch, 102, (0, 0, 0, 0, 0, 0)), {}, (malformed,))
    with pytest.raises(SpecValidationError, match="Invalid mapping range"):
        NativeLinuxPolicy(uid=1000).preflight(pre)


def test_mapping_length_bounds_checked_before_page_iteration():
    arch = ArchX86()
    policy = NativeLinuxPolicy()
    policy.mmaps[0x5000] = 4096
    mapping = {"start": 0x5000, "end": 0x6000, "perms": "rw-", "private": True}
    for number in (11, 10):
        pre = snapshot(
            arch,
            syscall(arch, number, (0x5000, 1 << 63, 0, 0, 0, 0)),
            {},
            (mapping,),
        )
        with pytest.raises(UnsupportedNativeEvent, match="Invalid mapping"):
            policy.preflight(pre)


def test_ioctl_signal_mask_prlimit_and_writev_bounds():
    arch = ArchX86()
    policy = NativeLinuxPolicy()
    ioctl_pre = snapshot(
        arch, syscall(arch, 16, (1, 21523, 0x2000, 0, 0, 0)), {0x2000: b"........"}
    )
    token = policy.preflight(ioctl_pre)
    policy.validate(
        ioctl_pre,
        successor(ioctl_pre, (-25) & ((1 << 64) - 1)),
        NativeStep("instruction"),
        token,
    )
    sig_pre = snapshot(
        arch,
        syscall(arch, 14, (0, 0x2000, 0x3000, 8, 0, 0)),
        {0x2000: b"\0" * 8, 0x3000: b"........"},
    )
    token = policy.preflight(sig_pre)
    policy.validate(
        sig_pre,
        successor(sig_pre, 0, memory={0x2000: b"\0" * 8, 0x3000: b"\0" * 8}),
        NativeStep("instruction"),
        token,
    )
    dangerous = snapshot(
        arch,
        syscall(arch, 14, (0, 0x2000, 0, 8, 0, 0)),
        {0x2000: (1 << 14).to_bytes(8, "little")},
    )
    with pytest.raises(UnsupportedNativeEvent, match="signal masks"):
        policy.preflight(dangerous)
    changed_limit = snapshot(
        arch, syscall(arch, 302, (123, 7, 0, 0x2000, 0, 0)), {0x2000: b"." * 16}
    )
    with pytest.raises(UnsupportedNativeEvent, match="pid-0 query-only"):
        policy.preflight(changed_limit)


def test_writev_byte_limit_and_unsupported_syscall():
    arch = ArchX86()
    iovec = (0x3000).to_bytes(8, "little") + (3).to_bytes(8, "little")
    pre = snapshot(
        arch, syscall(arch, 20, (1, 0x2000, 1, 0, 0, 0)), {0x2000: iovec, 0x3000: b"abc"}
    )
    policy = NativeLinuxPolicy()
    token = policy.preflight(pre)
    assert token.op == "writev"
    policy.validate(pre, successor(pre, 2, stdout=b"ab"), NativeStep("instruction"), token)
    with pytest.raises(SpecValidationError, match="write byte count"):
        policy.validate(pre, successor(pre, 4, stdout=b"abcd"), NativeStep("instruction"), token)
    bad = snapshot(
        arch, syscall(arch, 20, (1, 0x2000, 1025, 0, 0, 0)), {0x2000: iovec, 0x3000: b"abc"}
    )
    with pytest.raises(UnsupportedNativeEvent):
        NativeLinuxPolicy().preflight(bad)
