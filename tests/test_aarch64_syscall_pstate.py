"""PSTATE.SS is debugger control, not permission to ignore user flags.

AArch64 PSTATE: SS=21, DIT=24, SSBS=12, D=9, NZCV=31:28.
Linux arch/arm64/kernel/debug-monitors.c user_regs_reset_single_step
sets/clears SS according to TIF_SINGLESTEP. Native run-until uses continue
rather than single-step; the QEMU syscall transaction retains its own policy.
"""
import pytest

from focaccia.no_replay import NoReplayActionMismatch, validate_set_tid_transition
from test_aarch64_no_replay import tid_states


@pytest.mark.parametrize('stepping', [False, True])
def test_native_breakpoint_destination_clears_only_single_step_control(stepping):
    before, after = tid_states()
    before.write_register('CPSR', 0x60001000 | (int(stepping) << 21))
    after.write_register('CPSR', 0x60001000)
    assert validate_set_tid_transition(before, after, 11399, native_breakpoint_destination=True).expected_tid == 11399
    assert before.read_register('CPSR') == 0x60001000 | (int(stepping) << 21)
    assert after.read_register('CPSR') == 0x60001000


@pytest.mark.parametrize('bit', range(32))
def test_no_other_pstate_bit_can_change_in_native_syscall_transition(bit):
    before, after = tid_states()
    before.write_register('CPSR', 0x60201000)
    after.write_register('CPSR', 0x60001000 ^ (1 << bit))
    # Includes each NZCV bit, DIT, SSBS, all DAIF (including D), reserved bits,
    # and unexpected SS still set after continue-to-breakpoint.
    with pytest.raises(NoReplayActionMismatch, match='CPSR=.*observed'):
        validate_set_tid_transition(before, after, 11399, native_breakpoint_destination=True)


def test_qemu_default_contract_cannot_ignore_single_step_difference():
    before, after = tid_states()
    before.write_register('CPSR', 0x60201000)
    after.write_register('CPSR', 0x60001000)
    with pytest.raises(NoReplayActionMismatch, match='CPSR'):
        validate_set_tid_transition(before, after, 11399)
    after.write_register('CPSR', 0x60201000)
    validate_set_tid_transition(before, after, 11399)
