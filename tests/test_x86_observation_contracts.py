"""PC runtime calibration and source-level stale-live-hint guard regression."""
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
PC_PROBE = runpy.run_path(str(ROOT / 'tests/probes/x86_pc_observation_smoke.py'))


def test_compiled_actual_flags_getter_rejects_stale_live_hint(tmp_path):
    """Compile the actual return statement, with minimal C state/API doubles.

    This tests branch selection on stale live=true/running=false. It is NOT a
    claim to reproduce an actual atomic-step exception in a running QEMU.
    """
    compiler = shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
    if compiler is None:
        pytest.skip('C compiler required for exact getter guard harness')
    source = (ROOT / 'qemu/target/i386/gdbstub.c').read_text()
    getter = source.split('int x86_cpu_gdb_read_register', 1)[1].split('case IDX_FLAGS_REG:', 1)[1]
    statement = re.search(r'return gdb_get_reg32\(mem_buf,.*?;', getter, re.S).group(0)
    assert 'qatomic_read(&cs->running)' in statement
    harness = r'''
struct CPUState { int running; };
struct X86CPU { int tcg_flags_live; };
struct CPUX86State { unsigned eflags; };
#define qatomic_read(p) (*(p))
static unsigned computes, observed;
static unsigned cpu_compute_eflags(struct CPUX86State *env) {
    (void)env; computes++; return 0x206;
}
static int gdb_get_reg32(void *buffer, unsigned value) {
    (void)buffer; observed = value; return 4;
}
static int read_flags(struct CPUState *cs, struct X86CPU *cpu,
                      struct CPUX86State *env) {
    void *mem_buf = 0;
''' + statement + r'''
}
int main(void) {
    struct CPUState cs = {0};
    struct X86CPU cpu = {1};
    struct CPUX86State env = {0x202};
    /* Stale live hint, stopped CPU: raw debugger-written flags win. */
    if (read_flags(&cs, &cpu, &env) != 4 || observed != 0x202 || computes) return 1;
    env.eflags = 0xe57;
    if (read_flags(&cs, &cpu, &env) != 4 || observed != 0xe57 || computes) return 2;
    /* Actual live execution must compute the lazy flags. */
    cs.running = 1; env.eflags = 0x202;
    if (read_flags(&cs, &cpu, &env) != 4 || observed != 0x206 || computes != 1) return 3;
    /* Running alone is insufficient: exit/entry bookkeeping also matters. */
    cpu.tcg_flags_live = 0; env.eflags = 0x212;
    if (read_flags(&cs, &cpu, &env) != 4 || observed != 0x212 || computes != 1) return 4;
    cs.running = 0;
    if (read_flags(&cs, &cpu, &env) != 4 || observed != 0x212 || computes != 1) return 5;
    return 0;
}
'''
    c_file, binary = tmp_path / 'guard.c', tmp_path / 'guard'
    c_file.write_text(harness)
    subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(c_file), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    # Sensitivity control: the previous live-hint-only getter must fail the
    # stopped/stale-hint case. Only this local test double is modified.
    old_statement = re.sub(r'\s*&&\s*qatomic_read\(&cs->running\)', '', statement)
    assert old_statement != statement
    old_c, old_binary = tmp_path / 'old-guard.c', tmp_path / 'old-guard'
    old_c.write_text(harness.replace(statement, old_statement))
    # The old statement no longer uses cs; keep other compiler checks enabled.
    subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-parameter', str(old_c), '-o', str(old_binary)], check=True)
    assert subprocess.run([str(old_binary)], check=False).returncode == 1


def test_pc_fixture_successor_is_independent_of_return_metadata(tmp_path):
    binary = tmp_path / 'pc.elf'
    PC_PROBE['fixture'](binary)
    code = binary.read_bytes()[0x1000:]
    assert code[:7] == bytes.fromhex('b8270000000f05')
    assert PC_PROBE['RESUME'] == PC_PROBE['SYSCALL'] + 2
    assert PC_PROBE['RESUME'] != 0


@pytest.mark.skipif(not all(os.environ.get(name) for name in (
    'X86_PC_OLD_PACKAGE', 'X86_PC_NEW_PACKAGE')),
    reason='old/new PC-observation packaged QEMU runtime opt-in required')
def test_actual_tb_pc_and_non_tb_unavailability(tmp_path):
    old = PC_PROBE['observe'](Path(os.environ['X86_PC_OLD_PACKAGE']),
                              tmp_path / 'old', expect_legacy=True)
    new = PC_PROBE['observe'](Path(os.environ['X86_PC_NEW_PACKAGE']), tmp_path / 'new')
    assert old['events'][0]['direct_pc'] == 0
    assert old['events'][0]['planned_pc'] == PC_PROBE['ENTRY']
    assert new['events'][0]['direct_pc'] == PC_PROBE['ENTRY']
    assert new['events'][2]['pc'] == 0 and new['events'][2]['direct_pc'] is None
    assert new['events'][3]['direct_pc'] == PC_PROBE['RESUME']
    assert new['real_resumed_tb_pc_checked']
