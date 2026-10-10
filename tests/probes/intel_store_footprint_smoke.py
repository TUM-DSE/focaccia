"""Actual QEMU store-address evidence, including unexpected-write rejection.

Builds a tiny independent ELF fixture; does not synthesize instruction semantics
for the live Intel oracle. Also records optimized TCG for instrumentation review.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from focaccia.arch import supported_architectures
from focaccia.qemu.transport import (
    CAP_PC, CAP_STORE_FOOTPRINT, EVENT_TRANSLATION_BLOCK, EVENT_AARCH64_SVC_ENTRY,
    PluginEOFError, PluginLaunchIdentity, PluginListener, manifest_sha256,
)

ENTRY, DATA = 0x401000, 0x402000


def fixture(path):
    code = (b"\x48\xbb" + struct.pack("<Q", DATA) + b"\xb8\x01\0\0\0"
            b"\x83\xc0\x02\x88\x03\x83\xc0\x04\x88\x43\x01\xeb\0"
            b"\xc6\x03\x33\xb8\x3c\0\0\0\x31\xff\x0f\x05")
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, ENTRY, 64, 0, 0,
                         64, 56, 2, 0, 0, 0)
    segments = (struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x1000+len(code), 0x1000+len(code), 0x1000)
                + struct.pack("<IIQQQQQQ", 1, 6, 0x2000, DATA, DATA, 2, 2, 0x1000))
    image = (header + segments).ljust(0x1000, b"\0") + code
    path.write_bytes(image.ljust(0x2000, b"\0") + bytes(2))
    path.chmod(0o700)


def run(qemu, plugin, output, enabled):
    rows = []
    negative_control = None
    with tempfile.TemporaryDirectory(prefix="focaccia-store-smoke-") as tmp:
        binary = Path(tmp) / "fixture"
        fixture(binary)
        identity = PluginLaunchIdentity(hashlib.sha256(binary.read_bytes()).hexdigest(),
                                        manifest_sha256([str(binary)]), manifest_sha256({}),
                                        manifest_sha256({'profile': 'qemu64'}))
        listener = PluginListener(str(Path(tmp)/"socket"), supported_architectures["x86_64"],
                                  expected_identity=identity,
                                  required_capabilities=CAP_PC | (CAP_STORE_FOOTPRINT if enabled else 0))
        listener.start()
        option = ",".join((plugin, f"socket={listener.path}", "online-blocks=on",
                           "automatic-snapshots=off", f"binary-sha256={identity.binary_sha256}",
                           f"argv-sha256={identity.argv_sha256}", f"env-sha256={identity.env_sha256}",
                           f"cpu-sha256={identity.cpu_sha256}"))
        if enabled:
            option += ",online-store-footprint=on"
        command = [qemu, "-cpu", "qemu64", "-d", "op,op_opt", "-D", str(output)+".tcg",
                   "-plugin", option, str(binary)]
        process = subprocess.Popen(command, env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            listener._server.settimeout(10)
            transport, handshake = listener.accept()
            assert bool(handshake.capabilities & CAP_STORE_FOOTPRINT) == enabled
            while True:
                try:
                    event = transport.receive_event(timeout=10)
                except PluginEOFError:
                    assert rows[-1]["kind"] == EVENT_AARCH64_SVC_ENTRY
                    break
                row = {"kind": event.kind, "sequence": event.sequence, "pc": event.pc}
                if enabled:
                    footprint = transport.drain_store_footprint()
                    row["spans"] = [(s.address, s.size) for s in footprint.spans]
                    assert footprint.from_sequence == event.sequence - 1
                    assert footprint.to_sequence == event.sequence
                if event.kind == EVENT_TRANSLATION_BLOCK:
                    assert event.pc in (ENTRY, ENTRY+28)
                    expected = [] if event.pc == ENTRY else [(DATA, 1), (DATA+1, 1)]
                    if event.pc == ENTRY:
                        assert transport.memory_permissions(ENTRY, 1) == 13
                        assert transport.memory_permissions(DATA, 2) == 11
                        assert transport.memory_permissions(0, 1) == 0
                    if enabled:
                        assert row["spans"] == expected
                    if event.pc != ENTRY:
                        assert transport.read_memory(DATA, 2) == b"\x03\x07"
                        if enabled:
                            from intel_live_validate import compare_store_footprint, ValidationError
                            # Independent fixture expectations; actual observed
                            # addresses/values are never used as oracle inputs.
                            compare_store_footprint({DATA: 3, DATA+1: 7}, footprint)
                            try:
                                compare_store_footprint({DATA: 3}, footprint)
                            except ValidationError as error:
                                assert 'unexpected actual store byte' in str(error)
                                negative_control = str(error)
                            else:
                                raise AssertionError('unpredicted actual store accepted')
                elif event.kind == EVENT_AARCH64_SVC_ENTRY:
                    assert event.auxiliary == 60
                    if enabled:
                        assert row["spans"] == [(DATA, 1)]
                    assert transport.read_memory(DATA, 2) == b"\x33\x07"
                else:
                    raise AssertionError(event)
                rows.append(row)
                transport.advance()
            stdout, stderr = process.communicate(timeout=10)
            assert process.returncode == 0, stderr
            assert not stdout
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
            listener.close()
    if enabled:
        assert negative_control is not None
    result = {"enabled": enabled, "events": rows, "tcg_log": str(output)+".tcg",
              "unexpected_store_negative_control": negative_control}
    output.write_text(json.dumps(result, indent=2)+"\n")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--qemu", required=True)
    p.add_argument("--plugin", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--disabled", action="store_true")
    args = p.parse_args()
    print(json.dumps(run(args.qemu, args.plugin, args.output, not args.disabled)))


if __name__ == "__main__":
    main()
