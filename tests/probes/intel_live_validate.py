"""Fail-closed online source Intel/TIR validation at optimized QEMU TB boundaries.

No instruction behavior lives here: XED selects exact forms, TIR executes them.
All lazy memory inputs are obtained while the *pre* boundary is still paused.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

from focaccia.arch import supported_architectures
from focaccia.intel_client import IntelOracle, IntelOracleError, bits, bit_value
from focaccia.qemu.transport import (
    CAP_BOUNDARY_SNAPSHOTS, CAP_INTEGER, CAP_MEMORY_PERMISSIONS, CAP_PC, CAP_STATUS, CAP_STORE_FOOTPRINT, CAP_VECTOR,
    EVENT_AARCH64_SVC_ENTRY, EVENT_AARCH64_SVC_SUCCESSOR, EVENT_TRANSLATION_BLOCK,
    MemoryAccessError, PluginEOFError, PluginLaunchIdentity, PluginListener, SnapshotPlan, manifest_sha256,
)
from intel_snapshot_smoke import sha256, elf_entry, INPUT, SNAPSHOT_REGISTERS

EXPECTED_SHA256 = '713784ad24639a95b1c764f5cced9985c72fff472df3c4650e8ac8f05f4cc922'
GPRS = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
CPU_FIELDS = ['GPR', 'ZMM', 'RIP', 'RFLAGS', 'FS', 'GS']
FIELDS = [*CPU_FIELDS, 'Next_IP', 'User_Environment_Cutpoint',
          'User_Count', 'User_Address', 'User_Byte', 'User_Dirty',
          'User_Syscall_Pre_GPR', 'User_Syscall_Pre_RFLAGS', 'User_Syscall_Pre_RIP']


class ValidationError(RuntimeError):
    pass


def guest_range(address, size, limit):
    if limit is not None and (type(address) is not int or type(size) is not int or size <= 0 or not 0 <= address <= limit-size):
        raise ValidationError(f'guest range {address!r}+{size!r} outside address profile [0,{limit:#x})')


def physical_prefixes(code):
    """Legacy prefix bytes, including mandatory SIMD66 discarded by XED osz.

    This is encoding-context extraction only. XED remains the exact form and
    effective operand/address-size decoder; no instruction behavior is supplied.
    """
    result = []
    for byte in code:
        if byte in (0xf0,0xf2,0xf3,0x2e,0x36,0x3e,0x26,0x64,0x65,0x66,0x67) or 0x40 <= byte <= 0x4f:
            result.append(byte)
        else:
            break
    return tuple(result)


def known_mask(known, width):
    if type(known) is bool:
        return (1 << width) - 1 if known else 0
    return bit_value(known, width)


def compare_bits(label, expected, known, actual, width):
    value, mask = bit_value(expected, width), known_mask(known, width)
    if (value ^ actual) & mask:
        raise ValidationError(f'{label}: expected {value:#x} mask {mask:#x}, observed {actual:#x}')


def segment_base(state, name):
    base_fields = 0xff0000ffffff0000
    if (known_mask(state['__known_'+name+'_descriptor'],64) & base_fields) != base_fields or (known_mask(state['__known_'+name+'_descriptor_high'],64) & 0xffffffff) != 0xffffffff:
        raise ValidationError(f'undefined {name} base prediction')
    descriptor = bit_value(state[name]['descriptor'],64)
    high = bit_value(state[name]['descriptor_high'],64)
    return ((descriptor >> 16) & 0xffffff) | (((descriptor >> 56) & 0xff) << 24) | ((high & 0xffffffff) << 32)


def compare_state(expected, actual, *, syscall_entry=False):
    prefix = 'User_Syscall_Pre_' if syscall_entry else ''
    for i, name in enumerate(GPRS):
        field = prefix + 'GPR'
        if known_mask(expected['__known_' + field][i],64) != 2**64-1:
            raise ValidationError(f'undefined required GPR prediction: {name}')
        compare_bits(name, expected[field][i], expected['__known_' + field][i], actual[name], 64)
    field = prefix + 'RFLAGS'
    compare_bits('RFLAGS', expected[field], expected['__known_' + field], actual['eflags'], 64)
    field = prefix + 'RIP'
    if known_mask(expected['__known_' + field], 64) != 2**64 - 1:
        raise ValidationError('undefined expected next PC')
    compare_bits('RIP', expected[field], expected['__known_' + field], actual['pc'], 64)
    for name in ('FS','GS'):
        base = segment_base(expected,name)
        if actual[name.lower()+'_base'] != base:
            raise ValidationError(f'{name} base: expected {base:#x}, observed {actual[name.lower()+"_base"]:#x}')
    for i in range(16):
        # Upper ZMM bits are not observable in this SSE-only processor profile.
        value = bit_value(expected['ZMM'][i], 512) & ((1 << 128) - 1)
        mask = known_mask(expected['__known_ZMM'][i], 512) & ((1 << 128) - 1)
        if mask != 2**128-1:
            raise ValidationError(f'undefined required XMM prediction: xmm{i}')
        compare_bits(f'xmm{i}', bits(value, 128), bits(mask, 128), actual[f'xmm{i}'], 128)


SYSCALL_CLOBBERS = frozenset(('rax', 'rcx', 'r11'))
NONLOCAL_SYSCALLS = frozenset((15, 56, 57, 58, 59, 322, 435))


def syscall_kernel_outputs(number, before):
    outputs = ['RAX', 'RCX', 'R11', 'OS-written memory', 'OS-memory-mapping changes']
    if number == 158 and before['rdi'] in (0x1001, 0x1002):
        outputs.append('gs_base' if before['rdi'] == 0x1001 else 'fs_base')
    return outputs


def compare_syscall_preserved(before, after, next_pc, number, *, check_pc=True):
    """Linux x86-64 ordinary-return ABI, not invented Intel CPU outputs.

    The entry observation has already been checked against the source-predicted
    CPU preaction state. The OS must preserve this independently captured input
    except for the explicitly named syscall clobbers/environment outputs.
    """
    if number in NONLOCAL_SYSCALLS:
        raise ValidationError('nonlocal/process-creation syscall outside ordinary-return contract')
    exempt = set(syscall_kernel_outputs(number, before))
    names = [n for n in GPRS if n not in SYSCALL_CLOBBERS]
    names += [f'xmm{i}' for i in range(16)] + ['eflags']
    names += [n for n in ('fs_base', 'gs_base') if n not in exempt]
    for name in names:
        if before[name] != after[name]:
            raise ValidationError(f'Linux syscall ABI preserved {name}: entry {before[name]:#x}, successor {after[name]:#x}')
    if check_pc and after['pc'] != next_pc:
        raise ValidationError(f'syscall resume PC: source expected {next_pc:#x}, observed {after["pc"]:#x}')


def syscall_negative_controls(before, after, next_pc, number, *, check_pc=True):
    compare_syscall_preserved(before,after,next_pc,number,check_pc=check_pc)
    results = []
    for name in ('rbx', 'xmm0'):
        corrupted = dict(after)
        corrupted[name] ^= 1
        try:
            compare_syscall_preserved(before, corrupted, next_pc, number,check_pc=check_pc)
        except ValidationError as rejection:
            results.append({'field':name, 'xor':1, 'rejection':str(rejection)})
        else:
            raise ValidationError(f'accepted deliberate syscall-preserved {name} corruption')
    return results


def dirty_bytes(state):
    if state.get('__known_User_Count') is not True:
        raise ValidationError('undefined memory evidence count')
    count = int(state['User_Count'])
    if not 0 <= count <= 4096:
        raise ValidationError('invalid memory evidence count')
    writes = {}
    for i in range(count):
        if state['__known_User_Dirty'][i] is not True:
            raise ValidationError('undefined dirty marker')
        if state['User_Dirty'][i]:
            if known_mask(state['__known_User_Address'][i], 64) != 2**64 - 1:
                raise ValidationError('undefined write address')
            if known_mask(state['__known_User_Byte'][i], 8) != 255:
                raise ValidationError('undefined write byte')
            writes[bit_value(state['User_Address'][i], 64)] = bit_value(state['User_Byte'][i], 8)
    return writes


class LiveModel:
    def __init__(self, oracle, decoder, transport, permissions, guest_limit=None, step_limit=10_000_000):
        self.oracle, self.decoder, self.transport = oracle, decoder, transport
        self.guest_limit = guest_limit
        self.step_limit = step_limit
        self.permissions = permissions
        self.signatures = {}
        self.syscall_prestate = None
        self.memory = {}
        self.memory_permissions = {}
        self.instructions = 0
        self.forms = set()
        self.initialized = False

    def overlay(self, state=None, arrays=None):
        self.oracle.checked({'op': 'overlay', 'state': state or {}, 'arrays': arrays or {},
                             'include_state': False})

    def boundary(self, observed):
        guest_range(observed['pc'],1,self.guest_limit)
        guest_range(observed['rsp'],1,self.guest_limit)
        # Execute source reset, never use evaluator's zero placeholders as evidence.
        self.oracle.checked({'op': 'initialize', 'function': 'User_Reset.0', 'include_state': False})
        self.memory = {}
        self.memory_permissions = {}
        self.syscall_prestate = None
        self.decoded = []
        patch = {'RIP': bits(observed['pc'], 64), 'RFLAGS': bits(observed['eflags'], 64),
                 'User_CPUID_SHA': False, 'CPUID_CET_SS': False,
                 'XCR0': {'AVX': bits(0, 1), 'ZMM_Hi256': bits(0, 1), 'Hi16_ZMM': bits(0, 1)}}
        # Original Compute_Linear_Address reads segment descriptor base fields.
        for seg in ('FS', 'GS'):
            base = observed[seg.lower() + '_base']
            patch[seg] = {'descriptor': bits(((base & 0xffffff) << 16) | ((base & 0xff000000) << 32) | 0x00920000000000, 64),
                          'descriptor_high': bits(base >> 32, 64)}
        # Explicit masks override observed-array marking in the same atomic
        # overlay. No APX/AVX: inaccessible registers/upper lanes stay unknown.
        patch.update({'__known_GPR': [bits(2**64-1 if i < 16 else 0, 64) for i in range(32)],
                      '__known_ZMM': [bits(2**128-1 if i < 16 else 0, 512) for i in range(32)]})
        self.overlay(patch, {'GPR': {str(i): bits(observed[n], 64) for i, n in enumerate(GPRS)},
                             'ZMM': {str(i): bits(observed[f'xmm{i}'], 512) for i in range(16)}})
        self.context = self.oracle.checked({'op': 'eval', 'function': 'User_Context.0', 'include_state': False})['result']
        self.initialized = True

    def supply(self, address):
        if address in self.memory:
            raise ValidationError(f'oracle requested already supplied memory {address:#x}')
        readable, writable = self.permissions(address)
        if not readable:
            raise ValidationError(f'no pre-boundary readable permission evidence at {address:#x}')
        value = self.transport.read_memory(address, 1)[0]
        self.oracle.checked({'op': 'eval', 'function': 'User_Supply.0',
                             'arguments': [bits(address, 64), bits(value, 8), readable, writable],
                             'include_state': False})
        self.memory[address] = value
        self.memory_permissions[address] = {'readable':readable, 'writable':writable}

    def step(self, instruction):
        if self.instructions >= self.step_limit:
            raise ValidationError('source step safety limit')
        f = dict(instruction.fields)
        context = copy.deepcopy(self.context)
        prefixes = physical_prefixes(instruction.code)
        operand_size = instruction.operand_size if instruction.operand_size != 8 else (64 if f['rexw'] else 16 if f['osz'] else 32)
        context.update(operand_size=operand_size, address_size=instruction.address_size,
                       lock_prefix_present=bool(f['lock']), osz_prefix_present=0x66 in prefixes,
                       asz_prefix_present=bool(f['asz']), rex_prefix_present=bool(f['rex']),
                       rex2_prefix_present=bool(f['rex2']), rep_prefix={0:0, 2:0xf2, 3:0xf3}[f['rep']])
        for dest, src in [('rex_w','rexw'), ('rex_r3','rexr'), ('rex_x3','rexx'), ('rex_b3','rexb'),
                          ('rex_r4','rexr4'), ('rex_x4','rexx4'), ('rex_b4','rexb4')]:
            context[dest] = bits(f[src], 1)
        if f['seg_ovd']:
            # In long mode XED discards legacy overrides; FS=4 and GS=5.
            name = {4:'FS', 5:'GS'}.get(f['seg_ovd'])
            if name is None:
                raise ValidationError('unknown XED segment override')
            context['segment'] = self.oracle.checked({'op':'state', 'fields':[name]})['state'][name]
            context['seg_prefix_present'] = True
        function = 'Step_' + instruction.iform + '.0'
        if function not in self.signatures:
            try:
                schema = self.oracle.checked({'op': 'schema', 'function': function})['schema']
            except IntelOracleError as error:
                raise ValidationError(f'{instruction.pc:#x} {instruction.iform} bytes={instruction.code.hex()}: {error}') from error
            self.signatures[function] = schema['arguments']
        values = {'context': context, 'ip': bits(instruction.form_ip, 64),
                  'opcode': bits(instruction.code[f['pos_nominal_opcode']], 8),
                  'mod': bits(f['mod'], 2), 'reg': bits(f['reg'], 3), 'rm': bits(f['rm'], 3),
                  'operand_size': operand_size, 'address_size': instruction.address_size}
        arguments = []
        for arg in self.signatures[function]:
            # The evaluator exposes TIR's alpha-renamed parameter identifiers.
            name = re.sub(r'_\d+$', '', arg['name'])
            if name not in values:
                raise ValidationError(f'unknown source argument {name!r}')
            arguments.append(values[name])
        request = {'op': 'eval', 'function': function, 'arguments': arguments, 'include_state': False}
        if instruction.iform == 'SYSCALL':
            # Preserve original source obligations, including partial flag masks,
            # before the named environment adapter performs CPU clobbers.
            self.syscall_prestate = self.oracle.checked({'op':'state','fields':CPU_FIELDS})['state']
        for _ in range(4097):
            result = self.oracle.request(request)
            if result['ok']:
                self.instructions += 1
                self.forms.add(instruction.iform)
                return
            error = result.get('error')
            if not isinstance(error, dict) or error.get('kind') != 'MissingMemory':
                raise ValidationError(f'{instruction.pc:#x} {instruction.iform}: {result}')
            if error.get('access') not in ('read', 'write', 'fetch'):
                raise ValidationError('missing or invalid memory diagnostic access kind')
            address = error['address']
            if isinstance(address, dict):
                address = bit_value(address, 64)
            elif type(address) is str and address.isascii() and address.isdecimal():
                address = int(address)
            if type(address) is not int or not 0 <= address < 2**64:
                raise ValidationError('invalid missing-memory address')
            self.supply(address)
        raise ValidationError('memory evidence safety limit')

    def predict(self, event):
        pc = event.pc
        for index in range(event.size):
            # Decode only immutable pre-boundary bytes, not inventory disassembly.
            guest_range(pc,1,self.guest_limit)
            window = min(15,self.guest_limit-pc) if self.guest_limit is not None else 15
            try:
                code = self.transport.read_memory(pc, window)
            except MemoryAccessError:
                code = bytearray()
                for offset in range(window):
                    try:
                        code.extend(self.transport.read_memory(pc + offset, 1))
                    except MemoryAccessError:
                        if not code:
                            raise
                        break
            instruction = self.decoder.decode(pc, bytes(code))
            code_permissions = self.transport.memory_permissions(pc, len(instruction.code))
            if type(code_permissions) is not int or code_permissions & ~15 or code_permissions & 12 != 12:
                raise ValidationError(f'no guest execute permission evidence for instruction at {pc:#x}')
            if index == event.size - 1 and pc != event.address:
                raise ValidationError('decoded final instruction does not match TB extent')
            self.decoded.append({'pc': instruction.pc, 'bytes': instruction.code.hex(),
                                 'iform': instruction.iform, 'guest_permissions':code_permissions})
            iterations = 0
            while True:
                self.step(instruction)
                iterations += 1
                state = self.oracle.checked({'op':'state','fields':
                    ['RIP','User_Environment_Cutpoint','Repeat_String_Operation']})['state']
                if state.get('__known_User_Environment_Cutpoint') is not True:
                    raise ValidationError('undefined environment cutpoint')
                if known_mask(state['__known_RIP'],64) != 2**64-1:
                    raise ValidationError('undefined predicted control flow')
                if state.get('__known_Repeat_String_Operation') is not True:
                    raise ValidationError('undefined repeat control')
                if not state['Repeat_String_Operation']:
                    break
                if (not instruction.iform.startswith('REP') or state['User_Environment_Cutpoint']
                        or bit_value(state['RIP'],64) != pc):
                    raise ValidationError('unsupported source repeat/cutpoint control')
                # Optimized QEMU completes REP internally in this no-debug,
                # no-asynchronous-event profile. Compose source stride-one
                # transitions to completion, before advancing QEMU even once.
            self.decoded[-1]['source_iterations'] = iterations
            if state['User_Environment_Cutpoint']:
                if index != event.size - 1:
                    raise ValidationError('environment cutpoint inside TB')
                break
            next_pc = bit_value(state['RIP'], 64)
            if index != event.size - 1 and next_pc != instruction.next_pc:
                raise ValidationError('model control transfer inside observed TB')
            pc = next_pc
        return self.oracle.checked({'op':'state', 'fields':FIELDS})['state']


def register_value(observation):
    width = 128 if observation.name.startswith('xmm') else 32 if observation.name == 'eflags' else 64
    if observation.num_bits != width or not 0 <= observation.value < 1 << width:
        raise ValidationError(f'invalid register evidence width/value for {observation.name}')
    return observation.value


def snapshot(transport, event, plans, guest_limit=None):
    if event.kind == EVENT_TRANSLATION_BLOCK:
        if event.pc not in plans:
            transport.install_snapshot_plan(SnapshotPlan(event.pc, 1, SNAPSHOT_REGISTERS))
            plans.add(event.pc)
        snap = transport.capture_snapshot(event.pc)
        result = {r.name: register_value(r) for r in snap.registers}
    else:
        result = {n: register_value(transport.read_register(n)) for n in SNAPSHOT_REGISTERS}
    for name in ('xmm15', 'fs_base', 'gs_base'):
        result[name] = register_value(transport.read_register(name))
    result['pc'] = event.pc
    guest_range(result['pc'],1,guest_limit)
    guest_range(result['rsp'],1,guest_limit)
    return result


def compare_store_footprint(writes, footprint):
    observed = set()
    for span in footprint.spans:
        if span.size not in (1,2,4,8,16) or not 0 <= span.address <= 2**64-span.size:
            raise ValidationError('invalid actual store footprint span')
        for address in range(span.address,span.address+span.size):
            if address not in writes:
                raise ValidationError(f'unexpected actual store byte at {address:#x}')
            observed.add(address)
    missing = set(writes) - observed
    if missing:
        raise ValidationError(f'predicted store byte absent from actual footprint: {min(missing):#x}')


def store_negative_control(writes, footprint):
    compare_store_footprint(writes,footprint)
    address = 0
    while address in writes:
        address += 1
    corrupted = SimpleNamespace(spans=(*footprint.spans,SimpleNamespace(address=address,size=1)))
    try:
        compare_store_footprint(writes,corrupted)
    except ValidationError as rejection:
        return {'extra_address':address, 'size':1, 'rejection':str(rejection)}
    raise ValidationError('accepted deliberate extra observed store')


def check_writes(transport, state, footprint, evidence=None, sequence=None):
    writes = dirty_bytes(state)
    compare_store_footprint(writes,footprint)
    actual = {address:transport.read_memory(address,1)[0] for address in writes}
    if evidence is not None:
        evidence.write(json.dumps({'kind':'actual-post-memory','sequence':sequence,'bytes':actual})+'\n')
        evidence.flush()
    for address, expected in writes.items():
        if expected != actual[address]:
            raise ValidationError(f'memory {address:#x}: expected {expected:#x}, observed {actual[address]:#x}')
    return len(writes)


class PermissionEvidence:
    """Fail closed until a guest-permission observer is supplied by transport."""
    def __init__(self, transport, guest_limit=None):
        self.transport = transport
        self.guest_limit = guest_limit

    def __call__(self, address):
        guest_range(address,1,self.guest_limit)
        observer = getattr(self.transport, 'memory_permissions', None)
        if observer is None:
            raise ValidationError('transport has no guest memory permission evidence API')
        result = observer(address, 1)
        if type(result) is not int or result < 0 or result & ~15:
            raise ValidationError('invalid memory permission evidence')
        if not result & 8:
            return False, False
        return bool(result & 1), bool(result & 2)


def run(args):
    if sha256(INPUT) != EXPECTED_SHA256:
        raise ValidationError('selected SHA input differs from approved fixture')
    manifest_path = args.model.with_name('manifest.json')
    manifest = json.loads(manifest_path.read_text())
    spec = importlib.util.spec_from_file_location('intel_decode', args.decoder_module)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    argv, env = ['sha256sum', str(INPUT)], {}
    address_limit = args.guest_limit if args.guest_limit is not None else args.reserved_va
    cpu_profile = {'architecture': {'isa':'x86_64', 'endianness':'little'},
                   'profile':'qemu64', 'asynchronous_signals':False, 'debug':False,
                   'flat_linux_user':True, 'cet':False, 'avx':False, 'sha':False,
                   'guest_reserved_va':args.reserved_va, 'guest_base':args.guest_base,
                   'guest_address_limit':address_limit, 'canonical_address_bits':48, 'la57':False}
    identity = PluginLaunchIdentity(sha256(args.binary), manifest_sha256(argv),
                                   manifest_sha256(env), manifest_sha256(cpu_profile))
    directory = tempfile.TemporaryDirectory(prefix='focaccia-intel-live-',dir='/tmp')
    # Freeze the exact private model used by this run; generator rebuilds cannot
    # change the source identity between hashing and evaluator startup.
    model_copy = Path(directory.name) / 'model.json'
    model_copy.write_bytes(args.model.read_bytes())
    listener = PluginListener(str(Path(directory.name) / 'plugin.sock'),
        supported_architectures['x86_64'], expected_identity=identity,
        required_capabilities=CAP_PC | CAP_INTEGER | CAP_STATUS | CAP_VECTOR | CAP_BOUNDARY_SNAPSHOTS | CAP_MEMORY_PERMISSIONS | CAP_STORE_FOOTPRINT)
    listener.start()
    qemu_path = str(Path(args.qemu).resolve(strict=True))
    plugin_path = str(Path(args.plugin).resolve(strict=True))
    option = ','.join((plugin_path, f'socket={listener.path}', 'start=0', 'stop=18446744073709551615',
        f'binary-sha256={identity.binary_sha256}', f'argv-sha256={identity.argv_sha256}',
        f'env-sha256={identity.env_sha256}', f'cpu-sha256={identity.cpu_sha256}',
        'online-blocks=on', 'automatic-snapshots=off', 'online-store-footprint=on'))
    command = [qemu_path, '-cpu', 'qemu64']
    if args.guest_base is not None:
        command += ['-B',str(args.guest_base)]
    if args.reserved_va is not None:
        command += ['-R',str(args.reserved_va)]
    command += ['-plugin', option, str(args.binary), *argv]
    stdout_path, stderr_path = Path(str(args.output)+'.stdout'), Path(str(args.output)+'.stderr')
    report = {'schema':'focaccia-intel-live-validation-v1', 'command':command,
              'model_sha256':sha256(model_copy), 'model_path':str(args.model),
              'oracle':args.oracle, 'decoder':str(args.decoder), 'binary_sha256':identity.binary_sha256,
              'cpu_profile':cpu_profile, 'semantic_validation':False, 'whole_program_completed':False,
              'validated_blocks':0, 'validated_instructions':0, 'predicted_source_steps':0, 'checked_write_bytes':0,
              'syscall_cutpoints':[], 'negative_control_rejected':False,
              'syscall_negative_controls':[], 'syscall_pc_negative_control':None,
              'store_footprint_coverage':False, 'store_negative_control':None,
              'events_received':0, 'store_footprints_checked':0, 'observed_store_records':0}
    report['model_provenance'] = {'manifest_sha256':sha256(manifest_path),
        'missing_implementations':manifest['missing_implementations'],
        'environment_bindings':manifest['environment_bindings']}
    process = None
    model = None
    evidence_path = Path(str(args.output) + '.evidence.jsonl')
    report['evidence_file'] = str(evidence_path)
    try:
        with evidence_path.open('w') as evidence, stdout_path.open('w') as stdout, stderr_path.open('w') as stderr, \
             IntelOracle(args.oracle, model_copy, timeout=args.timeout) as oracle, \
             module.Decoder(args.decoder, timeout=args.timeout) as decoder:
            process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr)
            listener._server.settimeout(min(args.timeout,0.25))
            deadline = time.monotonic()+args.timeout
            while True:
                try:
                    transport,handshake = listener.accept()
                    break
                except TimeoutError:
                    if process.poll() is not None:
                        stdout.flush(); stderr.flush()
                        raise ValidationError(f'QEMU exited before handshake ({process.returncode}): {stderr_path.read_text()[-4096:]}')
                    if time.monotonic() >= deadline:
                        raise ValidationError('QEMU handshake timeout')
            model = LiveModel(oracle, decoder, transport, PermissionEvidence(transport,address_limit),address_limit,args.instruction_limit)
            plans, pending, os_pending, os_obligation = set(), None, None, None
            pending_count = 0
            pending_pre_syscall = None
            first = True
            while True:
                try:
                    event = transport.receive_event(timeout=args.timeout)
                except PluginEOFError:
                    if pending is not None or os_pending not in (60, 231):
                        raise ValidationError('EOF without validated exit syscall entry')
                    break
                report['events_received'] += 1
                report['last_event'] = {'kind':event.kind, 'sequence':event.sequence, 'epoch':event.epoch,
                    'pc':event.pc, 'last_pc_or_argument0':event.address, 'instruction_count_or_size':event.size}
                footprint = transport.drain_store_footprint()
                report['observed_store_records'] += len(footprint.spans)
                for span in footprint.spans:
                    guest_range(span.address,span.size,address_limit)
                evidence.write(json.dumps({'kind':'actual-store-footprint',
                    'from_sequence':footprint.from_sequence, 'from_epoch':footprint.from_epoch,
                    'to_sequence':footprint.to_sequence, 'to_epoch':footprint.to_epoch,
                    'spans':[(s.address,s.size) for s in footprint.spans]})+'\n')
                evidence.flush()
                if event.kind == EVENT_AARCH64_SVC_ENTRY:
                    if pending is None or not pending['User_Environment_Cutpoint']:
                        raise ValidationError('unexpected syscall entry without model cutpoint')
                    observed = snapshot(transport, event, plans,address_limit)
                    evidence.write(json.dumps({'kind':'syscall-entry', 'sequence':event.sequence, 'observed':observed})+'\n')
                    evidence.flush()
                    if pending_pre_syscall is None:
                        raise ValidationError('syscall has no retained source pre-instruction obligation')
                    report['checked_write_bytes'] += check_writes(transport,pending,footprint,evidence,event.sequence)
                    report['store_footprints_checked'] += 1
                    compare_state(pending_pre_syscall, observed)
                    os_pending = event.auxiliary
                    if os_pending != observed['rax'] or event.address != observed['rdi']:
                        raise ValidationError('syscall event metadata disagrees with entry register evidence')
                    if os_pending in NONLOCAL_SYSCALLS:
                        raise ValidationError('syscall outside ordinary Linux user return contract')
                    if known_mask(pending['__known_Next_IP'],64) != 2**64-1:
                        raise ValidationError('undefined source syscall resume PC')
                    os_obligation = {'entry':dict(observed), 'next_pc':bit_value(pending['Next_IP'],64),
                                     'source_pc':event.pc, 'number':os_pending}
                    report['syscall_cutpoints'].append({'sequence':event.sequence, 'pc':event.pc,
                        'number':os_pending, 'argument0':observed['rdi'], 'cpu_prestate_checked':True,
                        'expected_resume_pc':os_obligation['next_pc'],
                        'environment_outputs':syscall_kernel_outputs(os_pending,observed)})
                    pending = None
                    pending_pre_syscall = None
                    report['validated_instructions'] += pending_count - 1  # SYSCALL itself is an environment cutpoint.
                    pending_count = 0
                    report['validated_blocks'] += 1
                    transport.advance()
                    continue
                if event.kind == EVENT_AARCH64_SVC_SUCCESSOR:
                    if os_pending is None or 'return_sequence' in report['syscall_cutpoints'][-1]:
                        raise ValidationError('syscall return without unique pending entry')
                    if os_pending in (60,231):
                        raise ValidationError('non-returning exit syscall unexpectedly returned')
                    if event.address != os_obligation['source_pc']:
                        raise ValidationError('syscall return cutpoint identity mismatch')
                    compare_store_footprint({},footprint)
                    report['store_footprints_checked'] += 1
                    observed = snapshot(transport,event,plans,address_limit)
                    # Return-event PC is unavailable: the current plugin's PC
                    # alias is event metadata, not an architectural RIP read.
                    observed.pop('pc')
                    evidence.write(json.dumps({'kind':'syscall-return', 'sequence':event.sequence,
                        'pc_evidence':'unavailable; mandatory source-PC check deferred to first resumed TB',
                        'observed':observed})+'\n')
                    evidence.flush()
                    compare_syscall_preserved(os_obligation['entry'],observed,os_obligation['next_pc'],os_pending,check_pc=False)
                    report['syscall_cutpoints'][-1].update(return_sequence=event.sequence,
                        return_abi_preserved_checked=True, return_pc_deferred=True,
                        observed_kernel_return=event.auxiliary)
                    if not report['syscall_negative_controls']:
                        report['syscall_negative_controls'] = syscall_negative_controls(
                            os_obligation['entry'],observed,os_obligation['next_pc'],os_pending,check_pc=False)
                    # Check again at the resumed TB: only declared outputs may be rebased.
                    transport.advance()
                    continue
                if event.kind != EVENT_TRANSLATION_BLOCK:
                    raise ValidationError(f'unexpected event kind {event.kind}')
                observed = snapshot(transport, event, plans,address_limit)
                evidence.write(json.dumps({'kind':'pre-boundary', 'sequence':event.sequence, 'epoch':event.epoch,
                    'instruction_count':event.size, 'last_pc':event.address, 'observed':observed})+'\n')
                evidence.flush()
                if first:
                    if event.pc != elf_entry(args.binary):
                        raise ValidationError('whole-program first boundary is not ELF entry')
                    first = False
                if pending is not None:
                    if pending['User_Environment_Cutpoint']:
                        raise ValidationError('missing syscall entry observation')
                    report['checked_write_bytes'] += check_writes(transport,pending,footprint,evidence,event.sequence)
                    report['store_footprints_checked'] += 1
                    compare_state(pending, observed)
                    report['validated_blocks'] += 1
                    report['validated_instructions'] += pending_count
                    if report['store_negative_control'] is None:
                        report['store_negative_control'] = store_negative_control(dirty_bytes(pending),footprint)
                    if not report['negative_control_rejected']:
                        corrupted = dict(observed)
                        corrupted['pc'] ^= 1
                        try:
                            compare_state(pending, corrupted)
                        except ValidationError as rejection:
                            report['negative_control_rejected'] = True
                            report['negative_control'] = {'sequence':event.sequence, 'field':'RIP',
                                'xor':1, 'rejection':str(rejection)}
                        else:
                            raise ValidationError('deliberate observed-state corruption was accepted')
                elif os_pending is not None:
                    if 'return_sequence' not in report['syscall_cutpoints'][-1]:
                        raise ValidationError('missing syscall return evidence')
                    compare_syscall_preserved(os_obligation['entry'],observed,os_obligation['next_pc'],os_pending)
                    if report['syscall_pc_negative_control'] is None:
                        corrupt = dict(observed,pc=observed['pc']^1)
                        try:
                            compare_syscall_preserved(os_obligation['entry'],corrupt,os_obligation['next_pc'],os_pending)
                        except ValidationError as rejection:
                            report['syscall_pc_negative_control'] = {'sequence':event.sequence,'xor':1,'rejection':str(rejection)}
                        else:
                            raise ValidationError('accepted corrupted resumed syscall PC')
                    report['syscall_cutpoints'][-1].update(successor_pc=event.pc, successor_abi_preserved_checked=True,
                                                         successor_source_pc_checked=True)
                    compare_store_footprint({},footprint)
                    report['store_footprints_checked'] += 1
                    os_pending = None
                    os_obligation = None
                else:
                    if report['events_received'] != 1:
                        raise ValidationError('TB without preceding source/environment obligation')
                    compare_store_footprint({},footprint)
                    report['store_footprints_checked'] += 1
                model.boundary(observed)
                pending = model.predict(event)
                pending_pre_syscall = model.syscall_prestate
                evidence.write(json.dumps({'kind':'prediction-before-advance', 'sequence':event.sequence,
                    'instructions':model.decoded, 'memory_inputs':model.memory,
                    'memory_permissions':model.memory_permissions, 'syscall_prestate':pending_pre_syscall,
                    'dirty_bytes':dirty_bytes(pending), 'predicted':{k:v for k,v in pending.items()
                    if k not in ('User_Address','User_Byte','User_Dirty','__known_User_Address',
                                 '__known_User_Byte','__known_User_Dirty')}})+'\n')
                evidence.flush()
                pending_count = len(model.decoded)
                report['predicted_source_steps'] = model.instructions
                report['forms'] = sorted(model.forms)
                if report['validated_blocks'] % 100 == 0:
                    print(f"validated {report['validated_blocks']} TBs / {model.instructions} source steps", file=sys.stderr, flush=True)
                    args.output.write_text(json.dumps(report, indent=2)+'\n')
                if model.instructions > args.instruction_limit:
                    raise ValidationError('instruction safety limit')
                transport.advance()
            process.wait(timeout=args.timeout)
            stdout.flush(); stderr.flush()
            report['stdout'], report['stderr'] = stdout_path.read_text(), stderr_path.read_text()
            expected = sha256(INPUT)
            if expected != EXPECTED_SHA256:
                raise ValidationError('SHA input changed during execution')
            if process.returncode != 0 or report['stdout'] != f'{expected}  {INPUT}\n' or (report['syscall_cutpoints'][-1]['argument0'] & 255) != process.returncode:
                raise ValidationError('terminal status or independent SHA-256 stdout mismatch')
            if not report['negative_control_rejected']:
                raise ValidationError('negative control did not execute')
            if len(report['syscall_negative_controls']) != 2 or report['syscall_pc_negative_control'] is None:
                raise ValidationError('syscall register/resume-PC negative controls did not execute')
            if report['store_negative_control'] is None:
                raise ValidationError('extra-store negative control did not execute')
            report['store_footprint_coverage'] = (report['store_footprints_checked'] == report['events_received'] > 0)
            if not report['store_footprint_coverage']:
                raise ValidationError('passive actual-store coverage incomplete; cannot claim full-memory validation')
            report.update(semantic_validation=True, whole_program_completed=True,
                          expected_sha256=expected, terminal={'kind':'validated-exit-syscall',
                          'syscall':os_pending, 'process_status':process.returncode})
            return report
    except Exception as error:
        report['failure'] = str(error)
        if model is not None:
            report['failure_oracle_checkpoint'] = {'decoded':getattr(model,'decoded',[]),
                'pre_memory_inputs':model.memory, 'syscall_prestate':model.syscall_prestate,
                'predicted_source_steps':model.instructions}
        raise
    finally:
        if process is not None and process.poll() is None:
            process.kill(); process.wait()
        listener.close()
        directory.cleanup()
        args.output.write_text(json.dumps(report, indent=2)+'\n')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--qemu', required=True)
    p.add_argument('--plugin', required=True)
    p.add_argument('--oracle', default='../tir/target/debug/intel-eval')
    p.add_argument('--model', type=Path, default=Path('/tmp/carbonara-usermode-full/typed.json'))
    p.add_argument('--decoder', type=Path, default=Path('/tmp/carbonara-xed/bin/intel-xed-decode'))
    p.add_argument('--decoder-module', type=Path, default=Path('../tir/scripts/intel_decode.py'))
    p.add_argument('--binary', type=Path, default=Path('/tmp/carbonara-sha-software/bin/busybox'))
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--guest-base', type=lambda value:int(value,0), help='explicit QEMU host/guest address offset')
    p.add_argument('--guest-limit', type=lambda value:int(value,0), help='assert all observed ordinary guest addresses below this bound')
    p.add_argument('--reserved-va', type=lambda value:int(value,0),
                   help='explicit guest VA reservation (bytes), bounded to canonical48 lower half')
    p.add_argument('--timeout', type=float, default=120)
    p.add_argument('--instruction-limit', type=int, default=10_000_000)
    args = p.parse_args(argv)
    if args.timeout <= 0 or args.instruction_limit <= 0:
        p.error('limits must be positive')
    for limit in (args.reserved_va,args.guest_limit):
        if limit is not None and (not 0 < limit <= 2**47 or limit % 4096):
            p.error('guest VA bounds must be page-aligned, positive, and at most 2**47')
    if args.guest_base is not None and (not 0 <= args.guest_base < 2**64 or args.guest_base % 4096):
        p.error('guest base must be a page-aligned unsigned address')
    run(args)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
