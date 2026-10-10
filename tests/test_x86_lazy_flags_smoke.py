"""Math and optional actual QEMU lazy-EFLAGS observation regression."""
import os
from pathlib import Path
import runpy

import pytest

PROBE = runpy.run_path(str(Path(__file__).parent / 'probes/x86_lazy_flags_smoke.py'))


def test_math_expected_checkpoints_and_unspecified_af_masks():
    expected = PROBE['expectations']()
    assert {name: value for name, (value, _) in expected.items()} == {
        'after_and': 0x206,
        'after_stc_std': 0x607,
        'after_cld_xor': 0x246,
        'after_overflow': 0xa96,
        'after_carry': 0x257,
        'after_auxcarry': 0x212,
    }
    for name in ('after_and', 'after_stc_std', 'after_cld_xor'):
        assert expected[name][1] == 0xffffffef  # AF undefined after logic
    for name in ('after_overflow', 'after_carry', 'after_auxcarry'):
        assert expected[name][1] == 0xffffffff


def test_parity_is_low_byte_and_sign_is_operand_width():
    flags = PROBE['logic_flags']
    assert flags(0xc0) == 0x206  # bit7 does not make a 32-bit value negative
    assert flags(0x1c0) == 0x206  # high bits do not change low-byte parity
    assert flags(1) == 0x202
    assert flags(0x80000001) == 0x282


def test_projection_removes_only_declared_fixture_plumbing(tmp_path):
    path = tmp_path / 'tcg.log'
    path.write_text('OP:\n add_i64 rax,rax,$0x1\n'
                    'OP after optimization and liveness analysis:\n'
                    ' call plugin(0x123),$0x2,$0\n'
                    ' st_i64 $0x123,env,$0xfffffff0\n'
                    ' mov_i64 rax,$0x7   sync: 0\n'
                    ' call cc_compute_all,$0x7,$1,tmp,cc_dst,cc_src\n'
                    ' exit_tb $0x123\n')
    assert PROBE['projected_optimized_ops'](path) == [
        'mov_i64 rax,$0x7', 'call cc_compute_all,$0x7,$1,tmp,cc_dst,cc_src']


@pytest.mark.skipif(not all(os.environ.get(name) for name in (
    'X86_FLAGS_OLD_PACKAGE', 'X86_FLAGS_NEW_PACKAGE', 'X86_FLAGS_AS', 'X86_FLAGS_LD')),
    reason='old/new packaged QEMU lazy-flags runtime opt-in required')
def test_actual_old_stale_new_correct_and_read_noninterference(tmp_path):
    binary, symbols = PROBE['build_fixture'](os.environ['X86_FLAGS_AS'],
                                            os.environ['X86_FLAGS_LD'], tmp_path)
    old = PROBE['observe'](Path(os.environ['X86_FLAGS_OLD_PACKAGE']), binary, symbols,
                            tmp_path / 'old', expect_stale=True)
    new = PROBE['observe'](Path(os.environ['X86_FLAGS_NEW_PACKAGE']), binary, symbols,
                            tmp_path / 'new')
    control = PROBE['observe'](Path(os.environ['X86_FLAGS_NEW_PACKAGE']), binary, symbols,
                                tmp_path / 'no-reads', read_flags=False)
    assert old['observed']['after_and'] == 0x202
    assert new['observed']['after_and'] == 0x206
    assert new['observed']['after_stc_std'] == 0x607
    assert old['guest_pushfq'] == new['guest_pushfq'] == control['guest_pushfq']
    projections = [PROBE['projected_optimized_ops'](tmp_path / case / 'tcg.log')
                   for case in ('old', 'new', 'no-reads')]
    assert projections[0] == projections[1] == projections[2]
    debugger = PROBE['gdb_write_roundtrip'](
        Path(os.environ['X86_FLAGS_NEW_PACKAGE']), binary, symbols['after_and'],
        tmp_path / 'debugger-writes.json')
    assert debugger['written_and_read_back'] == [0x202, 0xe57, 0x206]
    assert debugger['guest_pushfq_after_restoring'] == new['guest_pushfq']
