"""Calibrate x86 lazy-EFLAGS observations against math and guest PUSHFQ.

This is a debugger/plugin register-read regression, not an instruction oracle.
Only paused TB-boundary snapshots/read commands are used, never instruction exec
callbacks. Private Intel model inputs are neither loaded nor modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import struct
import time
import subprocess
import tempfile

from focaccia.arch import supported_architectures
from focaccia.qemu.transport import (
    CAP_BOUNDARY_SNAPSHOTS, CAP_PC, CAP_STATUS, EVENT_TRANSLATION_BLOCK,
    EVENT_AARCH64_SVC_ENTRY, PluginEOFError, PluginLaunchIdentity, PluginListener,
    SnapshotPlan, manifest_sha256,
)

CF, PF, AF, ZF, SF, DF, OF = 1, 4, 16, 64, 128, 1024, 2048
BASE = 0x202
ALL_FLAGS = (1 << 32) - 1
NAMES = ('after_and', 'after_stc_std', 'after_cld_xor',
         'after_overflow', 'after_carry', 'after_auxcarry')


def logic_flags(value, width=32):
    value &= (1 << width) - 1
    return BASE | (PF if (value & 255).bit_count() % 2 == 0 else 0) | (
        ZF if value == 0 else 0) | (SF if value >> (width - 1) else 0)


def add_flags(left, right, width=32):
    mask = (1 << width) - 1
    result = (left + right) & mask
    return logic_flags(result, width) | (CF if left + right > mask else 0) | (
        AF if (left ^ right ^ result) & 16 else 0) | (
        OF if (~(left ^ right) & (left ^ result)) >> (width - 1) & 1 else 0)


def expectations():
    # AND/XOR leave AF unspecified: never use a representative as a math claim.
    partial = ALL_FLAGS & ~AF
    return dict(zip(NAMES, (
        (logic_flags(0x12c0 & 0xff), partial),
        (logic_flags(0xc0) | CF | DF, partial),
        (logic_flags(0), partial),
        (add_flags(0x7fffffff, 1), ALL_FLAGS),
        (add_flags(0xffffffff, 1), ALL_FLAGS),
        (add_flags(0xf, 1), ALL_FLAGS),
    )))


def build_fixture(assembler, linker, directory):
    source = Path(__file__).with_suffix('.S')
    obj, binary = directory / 'flags.o', directory / 'flags.elf'
    subprocess.run([assembler, '--64', '-o', str(obj), str(source)], check=True)
    subprocess.run([linker, '-m', 'elf_x86_64', '-static', '-e', '_start',
                    '-o', str(binary), str(obj)], check=True)
    nm = str(Path(linker).with_name(Path(linker).name.removesuffix('ld') + 'nm'))
    listing = subprocess.check_output([nm, '--defined-only', str(binary)], text=True)
    symbols = {parts[2]: int(parts[0], 16) for line in listing.splitlines()
               if len(parts := line.split()) == 3}
    raw = binary.read_bytes()
    assert raw[:6] == b'\x7fELF\x02\x01'
    assert struct.unpack_from('<Q', raw, 24)[0] == symbols['_start']
    assert set(NAMES) | {'_start', 'captures'} <= symbols.keys()
    return binary, symbols


def projected_optimized_ops(path):
    """Fixture-only projection: omit plugin plumbing/host exits/liveness text."""
    active, result = False, []
    for line in path.read_text().splitlines():
        if line == 'OP:':
            active = False
        if line.startswith('OP after optimization'):
            active = True
            continue
        if not active:
            continue
        line = re.split(r'\s{2,}', line.strip())[0]
        if not line or line.startswith(('----', 'call plugin', 'exit_tb')):
            continue
        if re.match(r'st\w* .*env,\$0xffff', line):
            continue
        result.append(line)
    return result


def observe(package, binary, symbols, output, *, expect_stale=False, read_flags=True):
    output.mkdir(parents=True, exist_ok=True)
    package = package.resolve()
    qemu = package / 'bin/qemu-x86_64'
    plugin = package / 'lib/plugins/libfocaccia.so'
    profile = {'profile': 'qemu64', 'guest_base': '0x800000000000'}
    identity = PluginLaunchIdentity(hashlib.sha256(binary.read_bytes()).hexdigest(),
                                   manifest_sha256([str(binary)]), manifest_sha256({}),
                                   manifest_sha256(profile))
    rows, observed, captured = [], {}, None
    wanted = expectations()
    by_pc = {symbols[name]: name for name in NAMES}
    process = None
    with tempfile.TemporaryDirectory(prefix='x86-flags-observation-') as temp:
        listener = PluginListener(str(Path(temp) / 'socket'), supported_architectures['x86_64'],
                                  expected_identity=identity,
                                  required_capabilities=CAP_PC | CAP_STATUS | CAP_BOUNDARY_SNAPSHOTS)
        listener.start()
        option = ','.join((str(plugin), f'socket={listener.path}', 'online-blocks=on',
            'automatic-snapshots=off', f'binary-sha256={identity.binary_sha256}',
            f'argv-sha256={identity.argv_sha256}', f'env-sha256={identity.env_sha256}',
            f'cpu-sha256={identity.cpu_sha256}'))
        command = [str(qemu), '-cpu', 'qemu64', '-B', profile['guest_base'],
                   '-d', 'op,op_opt', '-D', str(output / 'tcg.log'),
                   '-plugin', option, str(binary)]
        try:
            process = subprocess.Popen(command, env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            listener._server.settimeout(20)
            transport, _ = listener.accept()
            while True:
                try:
                    event = transport.receive_event(timeout=20)
                except PluginEOFError:
                    assert rows[-1]['kind'] == EVENT_AARCH64_SVC_ENTRY and rows[-1]['auxiliary'] == 60
                    break
                row = {'kind': event.kind, 'pc': event.pc, 'size': event.size,
                       'sequence': event.sequence, 'auxiliary': event.auxiliary}
                if event.kind == EVENT_TRANSLATION_BLOCK:
                    if event.pc == symbols['_start']:
                        rsp = transport.read_register('rsp').value
                        assert 0 <= rsp < 1 << 47, f'noncanonical fixture stack: {rsp:#x}'
                        row['initial_rsp'] = rsp
                    name = by_pc.get(event.pc)
                    if name is not None and read_flags:
                        assert name not in observed
                        transport.install_snapshot_plan(SnapshotPlan(event.pc, 1, ('eflags', 'rsp')))
                        snapshot = transport.capture_snapshot(event.pc)
                        regs = {r.name: r for r in snapshot.registers}
                        assert regs['eflags'].num_bits == 32
                        value = regs['eflags'].value
                        assert 0 <= regs['rsp'].value < 1 << 47
                        # Multiple debugger getter calls must not change flags.
                        assert [transport.read_register('eflags').value for _ in range(3)] == [value] * 3
                        observed[name] = value
                        row.update(checkpoint=name, flags=value)
                elif event.kind == EVENT_AARCH64_SVC_ENTRY and event.auxiliary == 1:
                    captured = struct.unpack('<6Q', transport.read_memory(symbols['captures'], 48))
                    if read_flags:
                        # do_syscall is outside cpu_exec: materialized eflags
                        # must remain authoritative on both old and new builds.
                        row['materialized_flags'] = transport.read_register('eflags').value
                        assert row['materialized_flags'] == captured[-1]
                rows.append(row)
                transport.advance()
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, stderr
            assert captured is not None and stdout == struct.pack('<6Q', *captured)
            (output / 'guest-pushfq.bin').write_bytes(stdout)
            (output / 'stderr.txt').write_bytes(stderr)
        finally:
            if process is not None and process.poll() is None:
                process.kill(); process.wait()
            listener.close()
    mismatches = []
    for i, name in enumerate(NAMES):
        expected, mask = wanted[name]
        assert (captured[i] ^ expected) & mask == 0, (name, captured[i], expected, mask)
        if read_flags:
            actual = observed[name]
            if (actual ^ expected) & mask or actual != captured[i]:
                mismatches.append({'checkpoint': name, 'observed': actual,
                                   'expected': expected, 'mask': mask, 'pushfq': captured[i]})
    if read_flags:
        if expect_stale:
            assert observed['after_and'] == 0x202 and captured[0] == 0x206
            assert mismatches, 'old getter negative control unexpectedly passed'
        else:
            assert not mismatches, mismatches
    report = {'kind': 'x86-lazy-flags-observation-calibration', 'command': command,
              'read_flags': read_flags, 'expect_stale': expect_stale,
              'package_store_path': str(package),
              'fixture_source_sha256': hashlib.sha256(Path(__file__).with_suffix('.S').read_bytes()).hexdigest(),
              'binary_sha256': identity.binary_sha256, 'events': rows,
              'expected': wanted, 'observed': observed, 'guest_pushfq': captured,
              'mismatches': mismatches, 'materialized_syscall_read_checked': read_flags,
              'qualification': 'Register observation calibration only; no Intel oracle expectations supplied.'}
    (output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def gdb_write_roundtrip(package, binary, checkpoint, output):
    """Separate stopped-debugger calibration; excluded from optimizer proof.

    At after_and, lazy CC storage retains PF=1. Clearing PF through a stopped
    debugger must read back clear, not OR stale lazy flags back into eflags.
    """
    def packet(sock, command):
        payload = command.encode('ascii')
        sock.sendall(b'$' + payload + b'#' + f'{sum(payload) & 255:02x}'.encode())
        assert sock.recv(1) == b'+'
        assert sock.recv(1) == b'$'
        data = bytearray()
        while (byte := sock.recv(1)) != b'#':
            assert byte, 'GDB disconnected'
            data.extend(byte)
        checksum = b''
        while len(checksum) < 2:
            chunk = sock.recv(2 - len(checksum))
            assert chunk, 'GDB disconnected during checksum'
            checksum += chunk
        assert int(checksum, 16) == sum(data) & 255
        sock.sendall(b'+')
        return data.decode('ascii')

    with tempfile.TemporaryDirectory(prefix='flags-gdb-') as temp:
        endpoint = str(Path(temp) / 'socket')
        process = subprocess.Popen([str(package.resolve() / 'bin/qemu-x86_64'),
            '-cpu', 'qemu64', '-B', '0x800000000000', '-g', endpoint, str(binary)],
            env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    sock.connect(endpoint)
                    break
                except FileNotFoundError:
                    assert process.poll() is None and time.monotonic() < deadline
                    time.sleep(0.01)
            assert packet(sock, '?').startswith(('T05', 'S05'))
            assert packet(sock, f'Z0,{checkpoint:x},1') == 'OK'
            assert packet(sock, 'c').startswith(('T05', 'S05'))
            read = lambda: int.from_bytes(bytes.fromhex(packet(sock, 'p11')), 'little')
            original = read()
            assert original == 0x206
            values = []
            for value in (0x202, 0xe57, 0x206):
                assert packet(sock, 'P11=' + struct.pack('<I', value).hex()) == 'OK'
                actual = read()
                assert actual == value, (value, actual)
                values.append(actual)
            assert packet(sock, f'z0,{checkpoint:x},1') == 'OK'
            assert packet(sock, 'c').startswith('W00')
            stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stderr
            assert len(stdout) == 48 and struct.unpack_from('<Q', stdout)[0] == original
        finally:
            sock.close()
            if process.poll() is None:
                process.kill(); process.wait()
    report = {'stopped_after_and': original, 'written_and_read_back': values,
              'guest_pushfq_after_restoring': struct.unpack('<6Q', stdout),
              'qualification': 'Separate GDB breakpoint run, not used for optimizer comparison.'}
    output.write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--old-package', type=Path, required=True)
    p.add_argument('--new-package', type=Path, required=True)
    p.add_argument('--assembler', required=True)
    p.add_argument('--linker', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    binary, symbols = build_fixture(args.assembler, args.linker, args.output)
    old = observe(args.old_package, binary, symbols, args.output / 'old', expect_stale=True)
    new = observe(args.new_package, binary, symbols, args.output / 'new')
    control = observe(args.new_package, binary, symbols, args.output / 'new-no-flag-reads', read_flags=False)
    assert old['guest_pushfq'] == new['guest_pushfq'] == control['guest_pushfq']
    def shapes(report):
        return [(r['kind'], r['pc'], r['size']) for r in report['events']]
    assert shapes(old) == shapes(new) == shapes(control)
    projections = [projected_optimized_ops(args.output / folder / 'tcg.log')
                   for folder in ('old', 'new', 'new-no-flag-reads')]
    assert projections[0] == projections[1] == projections[2], 'optimized guest TCG projection changed'
    debugger = gdb_write_roundtrip(args.new_package, binary, symbols['after_and'],
                                  args.output / 'stopped-debugger-writes.json')
    assert list(debugger['guest_pushfq_after_restoring']) == list(new['guest_pushfq'])
    result = {'old_stale_flags_rejected': bool(old['mismatches']),
              'stopped_debugger_writes_remain_authoritative': True,
              'new_flags_match_math_and_pushfq': not new['mismatches'],
              'guest_captures_unchanged_by_reads': True,
              'tb_shapes_and_projected_guest_tcg_unchanged': True,
              'observed': new['observed'], 'qualification': 'Fixture-only optimizer check, not universal proof.'}
    (args.output / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
