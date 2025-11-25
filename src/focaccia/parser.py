"""Parsing of JSON files containing snapshot data."""

import re
import base64
import orjson as json
from typing import TextIO

from .arch import supported_architectures, Arch
from .snapshot import ProgramState
from .symbolic import SymbolicTransform
from .trace import Trace, TraceContainer, TraceEnvironment

class ParseError(Exception):
    """A parse error."""

def _get_or_throw(obj: dict, key: str):
    """Get a value from a dict or throw a ParseError if not present."""
    val = obj.get(key)
    if val is not None:
        return val
    raise ParseError(f'Expected value at key {key}, but found none.')

def parse_transformations(json_stream: TextIO) -> TraceContainer[SymbolicTransform]:
    """Parse symbolic transformations from a text stream."""
    data = json.loads(json_stream.read())

    env = TraceEnvironment.from_json(_get_or_throw(data, 'env'))
    strace = [SymbolicTransform.from_json(item) \
              for item in _get_or_throw(data, 'states')]

    return TraceContainer(strace, env)

def serialize_transformations(transforms: Trace[SymbolicTransform],
                              out_stream: TextIO):
    """Serialize symbolic transformations to a text stream."""
    data = json.dumps({
        'env': transforms.env.to_json(),
        'addrs': transforms.addresses,
        'states': [t.to_json() for t in transforms],
    }, option=json.OPT_INDENT_2).decode()
    out_stream.write(data)

def parse_snapshots(json_stream: TextIO) -> TraceContainer[ProgramState]:
    """Parse snapshots from our JSON format."""
    json_data = json.loads(json_stream.read())

    arch = supported_architectures[_get_or_throw(json_data, 'architecture')]
    env = TraceEnvironment.from_json(_get_or_throw(json_data, 'env'))
    snapshots = []
    for snapshot in _get_or_throw(json_data, 'snapshots'):
        state = ProgramState(arch)
        for reg, val in _get_or_throw(snapshot, 'registers').items():
            state.set_register(reg, val)
        for mem in _get_or_throw(snapshot, 'memory'):
            start, end = _get_or_throw(mem, 'range')
            data = base64.b64decode(_get_or_throw(mem, 'data'))
            assert(len(data) == end - start)
            state.write_memory(start, data)

        snapshots.append(state)

    return TraceContainer(snapshots, env)

def serialize_snapshots(snapshots: Trace[ProgramState], out_stream: TextIO):
    """Serialize a list of snapshots to out JSON format."""
    if not snapshots:
        empty = json.dumps({}, option=json.OPT_INDENT_2).decode()
        out_stream.write(empty)

    arch = snapshots[0].arch
    res = {
        'architecture': arch.archname,
        'env': snapshots.env.to_json(),
        'snapshots': []
    }
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

    data = json.dumps(res, option=json.OPT_INDENT_2).decode()
    out_stream.write(data)

def _make_unknown_env() -> TraceEnvironment:
    return TraceEnvironment('', [], False, [], '?')

def parse_qemu(stream: TextIO, arch: Arch) -> TraceContainer[ProgramState]:
    """Parse a QEMU log from a stream.

    Recommended QEMU log option: `qemu -d exec,cpu,fpu,vpu,nochain`. The `exec`
    flag is strictly necessary for the log to be parseable.

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

    return TraceContainer(states, _make_unknown_env())

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
                cur_state.set_register(regname, int(value, 16))

def parse_arancini(stream: TextIO, arch: Arch) -> TraceContainer[ProgramState]:
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
                states[-1].set_register(regname, int(value, 16))

    return TraceContainer(states, _make_unknown_env())

def parse_box64(stream: TextIO, arch: Arch) -> TraceContainer[ProgramState]:
    def parse_box64_flags(state: ProgramState, flags_dump: str):
        flags = ['O', 'D', 'S', 'Z', 'A', 'P', 'C']
        for i, flag in enumerate(flags):
            if flag == flags_dump[i]: # Flag is set
                state.set_register(arch.to_regname(flag + 'F'), 1)
            elif '-' == flags_dump[i]: # Flag is not set
                state.set_register(arch.to_regname(flag + 'F'), 0)

    trace_string = stream.read()

    blocks = re.split(r'(?=\nES=)', trace_string.strip())[1:]
    blocks = [block.strip() for block in blocks if block.strip()]

    states = []
    pattern = r'([A-Z0-9]{2,3}|flags|FLAGS)=([0-9a-fxODSZAPC?\-]+)'
    for block in blocks:
        states.append(ProgramState(arch))
        matches = re.findall(pattern, block)

        for regname, value in matches:
            if regname.lower() == "flags":
                parse_box64_flags(states[-1], value)
                continue

            regname = arch.to_regname(regname)
            if regname is not None:
                states[-1].set_register(regname, int(value, 16))

    return TraceContainer(states, _make_unknown_env())

