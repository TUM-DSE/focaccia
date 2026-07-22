"""Public persistence APIs and parsers for emulator text logs."""

import re
from typing import TextIO

from .arch import Arch
from .persistence import (
    SCHEMA_VERSION,
    AmbiguousArchitectureError,
    ArchitectureParseError,
    ExpressionWidthError,
    FieldTypeError,
    InstructionParseError,
    MissingFieldError,
    ParseError,
    StateParseError,
    TraceCardinalityError,
    TraceDecodeError,
    TraceKindError,
    TraceLimitError,
    TransformParseError,
    TruncatedTraceError,
    UnsupportedSchemaVersionError,
    parse_snapshots,
    parse_transformations,
    serialize_snapshots,
    serialize_transformations,
    stream_transformation,
)
from .snapshot import ProgramState
from .trace import MaterializedTrace, TraceEnvironment

__all__ = [
    "SCHEMA_VERSION",
    "AmbiguousArchitectureError",
    "ArchitectureParseError",
    "ExpressionWidthError",
    "FieldTypeError",
    "InstructionParseError",
    "MissingFieldError",
    "ParseError",
    "StateParseError",
    "TraceCardinalityError",
    "TraceDecodeError",
    "TraceKindError",
    "TraceLimitError",
    "TransformParseError",
    "TruncatedTraceError",
    "UnsupportedSchemaVersionError",
    "parse_snapshots",
    "parse_transformations",
    "serialize_snapshots",
    "serialize_transformations",
    "stream_transformation",
    "parse_qemu",
    "parse_arancini",
    "parse_box64",
]


def _make_unknown_env(arch: Arch) -> TraceEnvironment:
    return TraceEnvironment(
        None,
        (),
        (),
        binary_hash=None,
        replay_provenance=None,
        architecture=arch.key,
    )

def parse_qemu(stream: TextIO, arch: Arch) -> MaterializedTrace[ProgramState]:
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

    return MaterializedTrace(states, _make_unknown_env(arch))

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
                cur_state.write_register(regname, int(value, 16))

def parse_arancini(stream: TextIO, arch: Arch) -> MaterializedTrace[ProgramState]:
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
                states[-1].write_register(regname, int(value, 16))

    return MaterializedTrace(states, _make_unknown_env(arch))

def parse_box64(stream: TextIO, arch: Arch) -> MaterializedTrace[ProgramState]:
    def parse_box64_flags(state: ProgramState, flags_dump: str):
        flags = ['O', 'D', 'S', 'Z', 'A', 'P', 'C']
        for i, flag in enumerate(flags):
            if flag == flags_dump[i]: # Flag is set
                state.write_register(arch.to_regname(flag + 'F'), 1)
            elif '-' == flags_dump[i]: # Flag is not set
                state.write_register(arch.to_regname(flag + 'F'), 0)

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
                states[-1].write_register(regname, int(value, 16))

    return MaterializedTrace(states, _make_unknown_env(arch))

