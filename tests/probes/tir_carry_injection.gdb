# Test-only fault injection. This changes a QEMU guest register through its GDB
# stub, never host process memory. A marker proves exactly what was changed.
python
import gdb
import json
import os

_inject_pc = os.environ.get("FOCACCIA_SMOKE_INJECT_PC")
_inject_marker = os.environ.get("FOCACCIA_SMOKE_INJECT_MARKER")
_injected = False

def _inject_carry(event):
    global _injected
    if _inject_pc is None or _injected:
        return
    pc = int(gdb.selected_frame().read_register("pc"))
    if pc != int(_inject_pc, 0):
        return
    _injected = True
    before = int(gdb.selected_frame().read_register("cpsr"))
    gdb.execute("set $cpsr = %d" % (before ^ (1 << 29)), to_string=True)
    after = int(gdb.selected_frame().read_register("cpsr"))
    with open(_inject_marker, "x") as stream:
        json.dump({"schema": 1, "pc": pc, "register": "CPSR", "before": before,
                   "after": after, "mask": 1 << 29}, stream)
    if before ^ after != 1 << 29:
        raise RuntimeError("carry injection changed unexpected bits")

if _inject_pc is not None:
    if not _inject_marker:
        raise RuntimeError("missing injection marker path")
    gdb.events.stop.connect(_inject_carry)
end
