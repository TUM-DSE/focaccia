"""Live guest-page permission evidence check; not instruction validation."""
import argparse
import json
from pathlib import Path

import intel_snapshot_smoke as smoke
from focaccia.qemu.transport import CAP_MEMORY_PERMISSIONS, PluginTransport


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--plugin", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = []
    original = PluginTransport.capture_snapshot

    def checked_capture(transport, pc):
        snapshot = original(transport, pc)
        if not evidence:
            assert transport._capabilities & CAP_MEMORY_PERMISSIONS
            regs = {item.name: item.value for item in snapshot.registers}
            code = transport.memory_permissions(pc, 1)
            stack = transport.memory_permissions(regs["rsp"], 8)
            absent = transport.memory_permissions(0, 1)
            # This controlled static ELF has RX text and RW non-executable stack.
            # Guest page zero is not mapped. Check the advertised mapping state,
            # not debugger-read success or host mapping protections.
            assert code == 13, code
            assert stack == 11, stack
            assert absent == 0, absent
            evidence.append({"pc": pc, "rsp": regs["rsp"], "code": code,
                             "stack": stack, "null_page": absent})
        return snapshot

    PluginTransport.capture_snapshot = checked_capture
    try:
        report = smoke.observe(args.qemu, args.plugin, args.binary, args.output, 30)
    finally:
        PluginTransport.capture_snapshot = original
    assert evidence
    report["permission_evidence"] = evidence
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"events": report["event_count"], "permission_evidence": evidence}))


if __name__ == "__main__":
    main()
