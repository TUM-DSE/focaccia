"""Parsing of JSON files containing snapshot data."""

import base64
import json
import re
from typing import TextIO

from arch import supported_architectures, Arch
from snapshot import ProgramState

class ParseError(Exception):
    """A parse error."""

def _get_or_throw(obj: dict, key: str):
    """Get a value from a dict or throw a ParseError if not present."""
    val = obj.get(key)
    if val is not None:
        return val
    raise ParseError(f'Expected value at key {key}, but found none.')

def parse_snapshots(json_stream: TextIO) -> list[ProgramState]:
    """Parse snapshots from our JSON format."""
    json_data = json.load(json_stream)

    arch = supported_architectures[_get_or_throw(json_data, 'architecture')]
    snapshots = []
    for snapshot in _get_or_throw(json_data, 'snapshots'):
        state = ProgramState(arch)
        for reg, val in _get_or_throw(snapshot, 'registers').items():
            state.set(reg, val)
        for mem in _get_or_throw(snapshot, 'memory'):
            start, end = _get_or_throw(mem, 'range')
            data = base64.b64decode(_get_or_throw(mem, 'data'))
            assert(len(data) == end - start)
            state.write_memory(start, data)

        snapshots.append(state)

    return snapshots

def serialize_snapshots(snapshots: list[ProgramState], out_stream: TextIO):
    """Serialize a list of snapshots to out JSON format."""
    if not snapshots:
        return json.dump({}, out_stream)

    arch = snapshots[0].arch
    res = { 'architecture': arch.archname, 'snapshots': [] }
    for snapshot in snapshots:
        assert(snapshot.arch == arch)
        regs = {r: v for r, v in snapshot.regs.items() if v is not None}
        mem = []
        for addr, data in snapshot.mem._pages.items():
            mem.append({
                'range': [addr, addr + len(data)],
                'data': base64.b64encode(data).decode('ascii')
            })
        res['snapshots'].append({ 'registers': regs, 'memory': mem })

    json.dump(res, out_stream)

def parse_qemu(stream: TextIO, arch: Arch) -> list[ProgramState]:
    """Parse a QEMU log from a stream.

    :return: A list of parsed program states, in order of occurrence in the
             log.
    """
    states = []
    for line in stream:
        if line.startswith('Trace'):
            states.append(ProgramState(arch))
            continue
        if states:
            _parse_qemu_line(line, states[-1])

    return states

def _parse_qemu_line(line: str, cur_state: ProgramState):
    """Try to parse a single register-assignment line from a QEMU log.

    Set all registers for which the line specified values in a `ProgramState`
    object.

    :param line:      The log line to parse.
    :param cur_state: The state on which to set parsed register values.
    """
    line = line.strip()

    # Remove padding spaces around equality signs
    line = re.sub(' =', '=', line)
    line = re.sub('= +', '=', line)

    # Standardize register names
    line = re.sub('YMM0([0-9])',   lambda m: f'YMM{m.group(1)}', line)
    line = re.sub('FPR([0-9])',    lambda m: f'ST{m.group(1)}', line)

    # Bring each register assignment into a new line
    line = re.sub(' ([A-Z0-9]+)=', lambda m: f'\n{m.group(1)}=', line)

    # Remove all trailing information from register assignments
    line = re.sub('^([A-Z0-9]+)=([0-9a-f ]+).*$',
                  lambda m: f'{m.group(1)}={m.group(2)}',
                  line,
                  0, re.MULTILINE)

    # Now parse registers and their values from the resulting lines
    lines = line.split('\n')
    for line in lines:
        split = line.split('=')
        if len(split) == 2:
            regname, value = split
            value = value.replace(' ', '')
            regname = cur_state.arch.to_regname(regname)
            if regname is not None:
                cur_state.set(regname, int(value, 16))

def parse_arancini(stream: TextIO, arch: Arch) -> list[ProgramState]:
    aliases = {
        'Program counter': 'RIP',
        'flag ZF': 'ZF',
        'flag CF': 'CF',
        'flag OF': 'OF',
        'flag SF': 'SF',
        'flag PF': 'PF',
        'flag DF': 'DF',
    }

    states = []
    for line in stream:
        if line.startswith('INVOKE PC='):
            states.append(ProgramState(arch))
            continue

        # Parse a register assignment
        split = line.split(':')
        if len(split) == 2 and states:
            regname, value = split
            regname = arch.to_regname(aliases.get(regname, regname))
            if regname is not None:
                states[-1].set(regname, int(value, 16))

    return states

if __name__ == "__main__":
    from arch import x86
    with open('qemu.log', 'r') as file:
        states = parse_qemu(file, x86.ArchX86())
        print(f'Parsed {len(states)} states from QEMU log.')
    with open('dump.qemu', 'w') as file:
        serialize_snapshots(states, file)

    with open('emulator-log.txt', 'r') as file:
        states = parse_arancini(file, x86.ArchX86())
        print(f'Parsed {len(states)} states from Arancini log.')
    with open('dump.arancini', 'w') as file:
        serialize_snapshots(states, file)
    exit(0)
