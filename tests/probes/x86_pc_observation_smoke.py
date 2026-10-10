"""PC observation calibration: real TB PC, unavailable action-callback PC.

No instruction oracle inputs are synthesized. A returning getpid syscall gives
an independently known successor in a minimal fixed-byte ELF; deferred checking
must use that first resumed TB, not return-event metadata zero.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from focaccia.arch import supported_architectures
from focaccia.qemu.transport import (
    CAP_PC, CAP_BOUNDARY_SNAPSHOTS, CAP_MEMORY_PERMISSIONS, CAP_STORE_FOOTPRINT,
    EVENT_TRANSLATION_BLOCK, EVENT_AARCH64_SVC_ENTRY, EVENT_AARCH64_SVC_SUCCESSOR,
    PluginEOFError, PluginLaunchIdentity, PluginListener, SnapshotPlan, manifest_sha256,
)
from focaccia.snapshot import RegisterAccessError

ENTRY = 0x401000
SYSCALL = ENTRY + 5
RESUME = ENTRY + 7
EXIT_SYSCALL = RESUME + 7


def fixture(path):
    # mov eax,39; syscall; mov eax,60; xor edi,edi; syscall
    code = bytes.fromhex('b8270000000f05b83c00000031ff0f05')
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 62, 1, ENTRY,
                         64, 0, 0, 64, 56, 1, 0, 0, 0)
    size = 0x1000 + len(code)
    segment = struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, size, size, 0x1000)
    path.write_bytes((header + segment).ljust(0x1000, b'\0') + code)
    path.chmod(0o700)


def observe(package, output, *, expect_legacy=False):
    package = package.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = output / 'pc.elf'
    fixture(binary)
    profile = {'profile': 'qemu64', 'guest_base': '0x800000000000'}
    identity = PluginLaunchIdentity(hashlib.sha256(binary.read_bytes()).hexdigest(),
                                   manifest_sha256([str(binary)]), manifest_sha256({}),
                                   manifest_sha256(profile))
    rows = []
    with tempfile.TemporaryDirectory(prefix='x86-pc-observation-') as tmp:
        listener = PluginListener(str(Path(tmp) / 'socket'), supported_architectures['x86_64'],
            expected_identity=identity, required_capabilities=CAP_PC | CAP_BOUNDARY_SNAPSHOTS |
            CAP_MEMORY_PERMISSIONS | CAP_STORE_FOOTPRINT)
        listener.start()
        options = ','.join((str(package / 'lib/plugins/libfocaccia.so'),
            f'socket={listener.path}', 'online-blocks=on', 'automatic-snapshots=off',
            'online-store-footprint=on', f'binary-sha256={identity.binary_sha256}',
            f'argv-sha256={identity.argv_sha256}', f'env-sha256={identity.env_sha256}',
            f'cpu-sha256={identity.cpu_sha256}'))
        command = [str(package / 'bin/qemu-x86_64'), '-cpu', 'qemu64', '-B', profile['guest_base'],
                   '-plugin', options, str(binary)]
        process = subprocess.Popen(command, env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            listener._server.settimeout(20)
            transport, _ = listener.accept()
            while True:
                try:
                    event = transport.receive_event(timeout=20)
                except PluginEOFError:
                    assert rows[-1]['kind'] == EVENT_AARCH64_SVC_ENTRY and rows[-1]['auxiliary'] == 60
                    break
                footprint = transport.drain_store_footprint()
                assert not footprint.spans
                row = {'kind': event.kind, 'pc': event.pc, 'address': event.address,
                       'sequence': event.sequence, 'auxiliary': event.auxiliary,
                       'footprint_from': footprint.from_sequence, 'footprint_to': footprint.to_sequence}
                try:
                    pc = transport.read_register('rip')
                except RegisterAccessError:
                    row['direct_pc'] = None
                else:
                    assert pc.num_bits == 64
                    row['direct_pc'] = pc.value
                if event.kind == EVENT_TRANSLATION_BLOCK:
                    assert event.pc in (ENTRY, RESUME)
                    transport.install_snapshot_plan(SnapshotPlan(event.pc, 1, ('rip', 'rsp')))
                    snapshot = transport.capture_snapshot(event.pc)
                    regs = {r.name: r.value for r in snapshot.registers}
                    assert regs['rip'] == event.pc and 0 <= regs['rsp'] < 1 << 47
                    row['planned_pc'] = regs['rip']
                    if expect_legacy:
                        assert row['direct_pc'] == 0 != regs['rip']
                    else:
                        assert row['direct_pc'] == regs['rip']
                    assert transport.memory_permissions(event.pc, 1) == 13
                    if event.pc == RESUME:
                        # This is the deferred source-position obligation. It is
                        # checked at a real TB, never against return metadata0.
                        assert rows[-1]['kind'] == EVENT_AARCH64_SVC_SUCCESSOR
                        assert event.pc == SYSCALL + 2
                        row['deferred_successor_pc_checked'] = True
                else:
                    assert event.kind in (EVENT_AARCH64_SVC_ENTRY, EVENT_AARCH64_SVC_SUCCESSOR)
                    if expect_legacy:
                        assert row['direct_pc'] == 0
                    else:
                        assert row['direct_pc'] is None, 'action PC must not masquerade as a zero observation'
                rows.append(row)
                transport.advance()
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0 and not stdout, (process.returncode, stderr)
            (output / 'stderr.txt').write_bytes(stderr)
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
            listener.close()
    assert [(r['kind'], r['pc']) for r in rows] == [
        (EVENT_TRANSLATION_BLOCK, ENTRY), (EVENT_AARCH64_SVC_ENTRY, SYSCALL),
        (EVENT_AARCH64_SVC_SUCCESSOR, 0), (EVENT_TRANSLATION_BLOCK, RESUME),
        (EVENT_AARCH64_SVC_ENTRY, EXIT_SYSCALL),
    ]
    assert rows[2]['address'] == SYSCALL
    report = {'scope': 'PC observation calibration, not instruction semantics validation',
              'package': str(package), 'command': command, 'expect_legacy': expect_legacy,
              'events': rows, 'legacy_synthetic_zero_detected': expect_legacy,
              'non_tb_pc_unavailable': not expect_legacy,
              'real_resumed_tb_pc_checked': rows[3]['deferred_successor_pc_checked']}
    (output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-package', type=Path, required=True)
    parser.add_argument('--new-package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    old = observe(args.old_package, args.output / 'old', expect_legacy=True)
    new = observe(args.new_package, args.output / 'new')
    result = {k: new[k] for k in ('non_tb_pc_unavailable', 'real_resumed_tb_pc_checked')}
    result['old_synthetic_zero_rejected'] = old['legacy_synthetic_zero_detected']
    (args.output / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
