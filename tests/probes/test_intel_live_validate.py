"""Pure comparator negative controls; no QEMU output is an oracle input."""
import copy
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace

from focaccia.intel_client import IntelOracle, bits, bit_value
from intel_live_validate import (GPRS, LiveModel, PermissionEvidence, ValidationError, compare_state,
    compare_syscall_preserved, syscall_negative_controls, compare_store_footprint, store_negative_control,
    dirty_bytes, register_value, guest_range, physical_prefixes)


def fixture():
    state = {'GPR': [bits(i, 64) for i in range(16)],
             '__known_GPR': [bits(2**64-1, 64) for _ in range(16)],
             'RIP': bits(0x1234, 64), '__known_RIP': bits(2**64-1, 64),
             'RFLAGS': bits(0x202, 64), '__known_RFLAGS': bits(2**64-1, 64),
             'ZMM': [bits(i, 512) for i in range(16)],
             '__known_ZMM': [bits(2**128-1, 512) for _ in range(16)]}
    actual = {n:i for i,n in enumerate(GPRS)}
    actual.update(pc=0x1234, eflags=0x202)
    for name,base in [('FS',0x123456789abc),('GS',0x5678)]:
        state[name] = {'descriptor':bits(((base&0xffffff)<<16)|((base&0xff000000)<<32)|0x00920000000000,64),
                       'descriptor_high':bits(base>>32,64)}
        state['__known_'+name+'_descriptor'] = bits(2**64-1,64)
        state['__known_'+name+'_descriptor_high'] = bits(2**64-1,64)
        actual[name.lower()+'_base'] = base
    actual.update({f'xmm{i}':i for i in range(16)})
    return state, actual


class ComparisonTests(unittest.TestCase):
    def test_positive(self):
        compare_state(*fixture())

    def test_permissions_unavailable_fail_closed(self):
        with self.assertRaisesRegex(ValidationError, 'permission evidence'):
            PermissionEvidence(object())(0x1234)

    def test_register_width_evidence(self):
        for name, width in [('rax',64), ('eflags',32), ('xmm0',128), ('fs_base',64)]:
            self.assertEqual(register_value(SimpleNamespace(name=name,num_bits=width,value=7)), 7)
            with self.assertRaises(ValidationError):
                register_value(SimpleNamespace(name=name,num_bits=width//2,value=7))

    def test_guest_permission_bits(self):
        for flags, expected in [(0,(False,False)), (8,(False,False)),
                                (9,(True,False)), (11,(True,True)), (13,(True,False))]:
            calls = []
            def query(address, size):
                calls.append((address,size))
                return flags
            self.assertEqual(PermissionEvidence(SimpleNamespace(memory_permissions=query))(0x1000), expected)
            self.assertEqual(calls, [(0x1000,1)])
        with self.assertRaises(ValidationError):
            PermissionEvidence(SimpleNamespace(memory_permissions=lambda *_:16))(0x1000)

    def test_boolean_knownness_abi(self):
        state, actual = fixture()
        state['__known_GPR'] = [True] * 16
        state['__known_ZMM'] = [True] * 16
        compare_state(state, actual)
        actual['rax'] ^= 1
        with self.assertRaises(ValidationError):
            compare_state(state, actual)

    def test_observed_corruption_rejected(self):
        for name in ('pc', 'eflags', 'fs_base', 'gs_base', *GPRS, *(f'xmm{i}' for i in range(16))):
            with self.subTest(name=name):
                state, actual = fixture()
                actual[name] ^= 1
                with self.assertRaises(ValidationError):
                    compare_state(state, actual)

    def test_oracle_corruption_rejected(self):
        state, actual = fixture()
        state['GPR'][0] = bits(1, 64)
        with self.assertRaises(ValidationError):
            compare_state(state, actual)

    def test_unknown_gpr_or_observable_vector_fails_closed(self):
        for key,width in [('__known_GPR',64),('__known_ZMM',512)]:
            state,actual = fixture()
            state[key][0] = bits(0,width)
            with self.assertRaises(ValidationError):
                compare_state(state,actual)

    def test_undefined_flag_not_compared(self):
        state, actual = fixture()
        state['__known_RFLAGS'] = bits((2**64-1) ^ 16, 64)
        actual['eflags'] ^= 16
        compare_state(state, actual)

    def test_dirty_evidence(self):
        state = {'User_Count': '1', '__known_User_Count': True, 'User_Dirty': [True], '__known_User_Dirty':[True],
                 'User_Address':[bits(0x123,64)], '__known_User_Address':[bits(2**64-1,64)],
                 'User_Byte':[bits(42,8)], '__known_User_Byte':[bits(255,8)]}
        self.assertEqual(dirty_bytes(state), {0x123:42})
        for key, value in [('__known_User_Dirty',False), ('__known_User_Byte',bits(0,8)),
                           ('__known_User_Address',bits(0,64))]:
            bad = copy.deepcopy(state)
            bad[key][0] = value
            with self.assertRaises(ValidationError):
                dirty_bytes(bad)


class AddressProfileTests(unittest.TestCase):
    def test_physical_mandatory_prefixes_not_immediates(self):
        self.assertEqual(physical_prefixes(bytes.fromhex('660f6cc0')),(0x66,))
        self.assertEqual(physical_prefixes(bytes.fromhex('66480f6ec3')),(0x66,0x48))
        self.assertEqual(physical_prefixes(bytes.fromhex('b866000000')),())

    def test_lower_canonical_bounds(self):
        limit = 1<<47
        guest_range(0,1,limit)
        guest_range(limit-16,16,limit)
        for address,size in [(limit,1),(limit-1,2),(-1,1),(0xfffff67bedc0,1)]:
            with self.assertRaises(ValidationError):
                guest_range(address,size,limit)

    def test_out_of_profile_memory_is_never_queried(self):
        def query(*_):
            self.fail('queried a mapping outside the declared address profile')
        evidence = PermissionEvidence(SimpleNamespace(memory_permissions=query),1<<47)
        with self.assertRaises(ValidationError):
            evidence(0xfffff67bedc0)


class StoreFootprintTests(unittest.TestCase):
    def footprint(self, *spans):
        return SimpleNamespace(spans=tuple(SimpleNamespace(address=a,size=s) for a,s in spans))

    def test_exact_union_allows_overlapping_records(self):
        compare_store_footprint({0x100:7,0x101:8},self.footprint((0x100,2),(0x101,1)))
        compare_store_footprint({},self.footprint())

    def test_live_extra_store_control(self):
        result = store_negative_control({0:7,1:8},self.footprint((0,2)))
        self.assertEqual(result['extra_address'],2)
        self.assertIn('unexpected actual store',result['rejection'])

    def test_negative_control_requires_positive_baseline(self):
        with self.assertRaises(ValidationError):
            store_negative_control({},self.footprint((0,1)))

    def test_extra_store_rejected_even_without_changed_value(self):
        # Store-address evidence is independent of final byte equality.
        with self.assertRaisesRegex(ValidationError,'unexpected actual store'):
            compare_store_footprint({0x100:7},self.footprint((0x100,2)))
        with self.assertRaisesRegex(ValidationError,'unexpected actual store'):
            compare_store_footprint({},self.footprint((0x100,1)))

    def test_missing_store_evidence_rejected(self):
        with self.assertRaisesRegex(ValidationError,'absent from actual footprint'):
            compare_store_footprint({0x100:7},self.footprint())

    def test_malformed_footprint_rejected(self):
        for address,size in [(0,0),(0,32),(2**64-1,2),(-1,1)]:
            with self.assertRaises(ValidationError):
                compare_store_footprint({},self.footprint((address,size)))


class SyscallPreservationTests(unittest.TestCase):
    def fixture(self):
        _, before = fixture()
        before.update(fs_base=0x123400,gs_base=0)
        after = dict(before,pc=0x1236)
        for name in ('rax','rcx','r11'):
            after[name] ^= 0x111
        return before,after

    def test_only_explicit_clobbers_exempt(self):
        before,after = self.fixture()
        compare_syscall_preserved(before,after,0x1236,0)
        for name in ('rbx','rsp','rdi','xmm0','xmm15','eflags','fs_base','gs_base','pc'):
            with self.subTest(name=name):
                corrupt = dict(after)
                corrupt[name] ^= 1
                with self.assertRaises(ValidationError):
                    compare_syscall_preserved(before,corrupt,0x1236,0)

    def test_deferred_pc_must_match_first_resumed_tb(self):
        before,after = self.fixture()
        returned = dict(after)
        returned.pop('pc')
        compare_syscall_preserved(before,returned,0x1236,0,check_pc=False)
        controls = syscall_negative_controls(before,returned,0x1236,0,check_pc=False)
        self.assertEqual(len(controls),2)
        wrong_resume = dict(after,pc=0x1237)
        with self.assertRaisesRegex(ValidationError,'resume PC'):
            compare_syscall_preserved(before,wrong_resume,0x1236,0)
        compare_syscall_preserved(before,after,0x1236,0)

    def test_live_syscall_negative_controls(self):
        before,after = self.fixture()
        controls = syscall_negative_controls(before,after,0x1236,0)
        self.assertEqual([x['field'] for x in controls],['rbx','xmm0'])

    def test_negative_controls_require_positive_baseline(self):
        before,after = self.fixture()
        after['rbx'] ^= 1
        with self.assertRaises(ValidationError):
            syscall_negative_controls(before,after,0x1236,0)

    def test_only_declared_arch_prctl_base_exempt(self):
        before,after = self.fixture()
        before['rdi'] = after['rdi'] = 0x1002
        after['fs_base'] = 0x999000
        compare_syscall_preserved(before,after,0x1236,158)
        with self.assertRaises(ValidationError):
            compare_syscall_preserved(before,after,0x1236,0)
        after['gs_base'] = 7
        with self.assertRaises(ValidationError):
            compare_syscall_preserved(before,after,0x1236,158)

    def test_nonlocal_returns_fail_closed(self):
        before,after = self.fixture()
        for number in (15,56,57,58,59,322,435):
            with self.assertRaises(ValidationError):
                compare_syscall_preserved(before,after,0x1236,number)


class RepeatCompositionTests(unittest.TestCase):
    def test_repeat_composes_source_before_any_guest_advance(self):
        pc = 0x1000
        instruction = SimpleNamespace(pc=pc,code=bytes.fromhex('f348ab'),iform='REP_STOSQ',next_pc=pc+3)
        count = [0]
        def checked(request):
            if request.get('fields') == ['RIP','User_Environment_Cutpoint','Repeat_String_Operation']:
                repeating = count[0] < 3
                return {'state':{'RIP':bits(pc if repeating else pc+3,64), '__known_RIP':bits(2**64-1,64),
                    'User_Environment_Cutpoint':False,'__known_User_Environment_Cutpoint':True,
                    'Repeat_String_Operation':repeating,'__known_Repeat_String_Operation':True}}
            return {'state':{'completed':True}}
        transport = SimpleNamespace(read_memory=lambda a,n:instruction.code+b'\x90'*(n-3),
            memory_permissions=lambda a,n:13)
        model = LiveModel(SimpleNamespace(checked=checked),SimpleNamespace(decode=lambda a,b:instruction),transport,None)
        model.decoded = []
        model.step = lambda insn:count.__setitem__(0,count[0]+1)
        result = model.predict(SimpleNamespace(pc=pc,address=pc,size=1))
        self.assertTrue(result['completed'])
        self.assertEqual(count[0],3)
        self.assertEqual(model.decoded[0]['source_iterations'],3)
        # No advance method exists: prediction cannot advance the guest.


class LazyInputTests(unittest.TestCase):
    def instruction(self):
        fields = {name:0 for name in ('lock','osz','asz','rex','rex2','rep','rexw','rexr',
                  'rexx','rexb','rexr4','rexx4','rexb4','seg_ovd','pos_nominal_opcode','mod','reg','rm')}
        return SimpleNamespace(fields=tuple(fields.items()), pc=0x1000, code=b'\x90',
                               form_ip=0x1001, operand_size=32, address_size=64, iform='NOP_90')

    def model(self, replies, permission=(True, False)):
        calls, reads = [], []
        def checked(request):
            calls.append(copy.deepcopy(request))
            if request['op'] == 'schema':
                return {'schema':{'arguments':[{'name':f'{n}_{i}'} for i,n in enumerate(
                    ('context','ip','opcode','mod','reg','rm','operand_size','address_size'))]}}
            return {'ok':True}
        def request(value):
            calls.append(copy.deepcopy(value))
            return replies.pop(0)
        def read(address, size):
            reads.append((address,size))
            return b'\x5a'
        oracle = SimpleNamespace(checked=checked, request=request)
        model = LiveModel(oracle, None, SimpleNamespace(read_memory=read), lambda _:permission)
        model.context = {}
        return model, calls, reads

    def test_missing_memory_retries_identical_step(self):
        model, calls, reads = self.model([
            {'ok':False, 'error':{'kind':'MissingMemory', 'address':bits(0x2000,64), 'access':'read'}}, {'ok':True}])
        model.step(self.instruction())
        attempts = [c for c in calls if c.get('function') == 'Step_NOP_90.0' and c['op'] == 'eval']
        self.assertEqual(attempts[0], attempts[1])
        supplies = [c for c in calls if c.get('function') == 'User_Supply.0']
        self.assertEqual(supplies[0]['arguments'], [bits(0x2000,64), bits(0x5a,8), True, False])
        self.assertEqual(reads, [(0x2000,1)])
        self.assertEqual(model.instructions, 1)

    def test_byte_form_and_rep_decoder_context(self):
        model, calls, _ = self.model([{'ok':True}])
        instruction = self.instruction()
        instruction.operand_size = 8
        fields = dict(instruction.fields)
        fields['rep'] = 3
        instruction.fields = tuple(fields.items())
        model.step(instruction)
        context = calls[-1]['arguments'][0]
        self.assertEqual(context['rep_prefix'], 0xf3)
        self.assertEqual(context['operand_size'], 32)

    def test_unstructured_missing_memory_is_not_zero_filled(self):
        model, calls, reads = self.model([{'ok':False, 'error':'missing memory'}])
        with self.assertRaises(ValidationError):
            model.step(self.instruction())
        self.assertEqual(reads, [])
        self.assertFalse(any(c.get('function') == 'User_Supply.0' for c in calls))

    def test_unavailable_permission_prevents_read(self):
        model, calls, reads = self.model([], (False, False))
        with self.assertRaises(ValidationError):
            model.supply(0x2000)
        self.assertEqual(reads, [])
        self.assertEqual(calls, [])

    def test_repeated_missing_supplied_address_rejected(self):
        model, calls, reads = self.model([])
        model.supply(0x2000)
        with self.assertRaises(ValidationError):
            model.supply(0x2000)
        self.assertEqual(reads, [(0x2000,1)])


@unittest.skipUnless(os.environ.get('INTEL_LIVE_MODEL'), 'private Intel model opt-in required')
class SourceIntegrationTests(unittest.TestCase):
    """Arithmetic fixtures, not QEMU-derived expectations or workload claims."""
    def setUp(self):
        path = Path(os.environ.get('INTEL_LIVE_DECODER_MODULE','../tir/scripts/intel_decode.py'))
        spec = importlib.util.spec_from_file_location('intel_decode_fixture',path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.oracle = IntelOracle(os.environ.get('INTEL_LIVE_ORACLE','../tir/target/debug/intel-eval'),
                                  Path(os.environ['INTEL_LIVE_MODEL']))
        self.addCleanup(self.oracle.close)
        self.decoder = module.Decoder(Path(os.environ.get('INTEL_LIVE_DECODER','/tmp/carbonara-xed/bin/intel-xed-decode')))
        self.addCleanup(self.decoder.close)
        self.model = LiveModel(self.oracle,self.decoder,
            SimpleNamespace(read_memory=lambda a,n:bytes((a+i)&255 for i in range(n))), lambda a:(True,True))
        observed = {n:0xf123456789abc000+i for i,n in enumerate(GPRS)}
        observed.update({f'xmm{i}':0x89abcdef012345670123456789abcdef ^ i for i in range(16)})
        observed.update(pc=0,eflags=0x202,fs_base=0,gs_base=0,rdi=0x2000,rsp=0x123456789000)
        self.observed = observed
        self.model.boundary(observed)

    def state(self, *fields):
        return self.oracle.checked({'op':'state','fields':list(fields)})['state']

    def test_source_rex_boolean_byte_register_selection(self):
        for code,expected in [('400fb6f6',self.observed['rsi']&255),
                              ('0fb6f6',(self.observed['rdx']>>8)&255)]:
            self.model.boundary(self.observed)
            self.model.step(self.decoder.decode(0,bytes.fromhex(code)))
            state = self.state('GPR','RFLAGS')
            self.assertEqual(bit_value(state['GPR'][6],64),expected)
            self.assertEqual(bit_value(state['RFLAGS'],64),self.observed['eflags'])

    def test_source_not_bits_primitive(self):
        self.model.step(self.decoder.decode(0,bytes.fromhex('48f7d2')))
        state = self.state('GPR','RFLAGS')
        self.assertEqual(bit_value(state['GPR'][2],64),self.observed['rdx']^((1<<64)-1))
        self.assertEqual(bit_value(state['RFLAGS'],64),self.observed['eflags'])

    def test_source_segment_base_binding(self):
        observed = dict(self.observed,fs_base=0x123456789abc,gs_base=0x76543210fedc)
        self.model.boundary(observed)
        state = self.state('GPR','ZMM','RIP','RFLAGS','FS','GS')
        for name in ('FS','GS'):
            result = self.oracle.checked({'op':'eval','function':'Get_Segment_Base.0',
                'arguments':[state[name]],'include_state':False})['result']
            self.assertEqual(bit_value(result,64),observed[name.lower()+'_base'])
        compare_state(state,observed)

    def test_source_xor_with_partial_vector_evidence(self):
        self.model.step(self.decoder.decode(0,bytes.fromhex('31ed')))
        state = self.state('GPR','RIP','RFLAGS')
        self.assertEqual(bit_value(state['GPR'][5],64),0)
        self.assertEqual(bit_value(state['RIP'],64),2)
        mask = bit_value(state['__known_RFLAGS'],64)
        self.assertEqual(mask,(1<<64)-1-16)  # XOR makes only AF unspecified.
        self.assertEqual((bit_value(state['RFLAGS'],64)^0x246)&mask,0)

    def test_source_xmm_accesses_only_observed_low_lanes(self):
        response = self.oracle.checked({'op':'eval','function':'Read_XMM.0',
            'arguments':[128,bits(0,5)],'include_state':False})
        self.assertEqual(bit_value(response['result'],128),self.observed['xmm0'])
        replacement = self.observed['xmm0'] ^ ((1<<128)-1)
        self.oracle.checked({'op':'eval','function':'Write_XMM.0',
            'arguments':[128,bits(0,5),bits(replacement,128),False],'include_state':False})
        state = self.state('ZMM')
        self.assertEqual(bit_value(state['ZMM'][0],512)&((1<<128)-1),replacement)
        self.assertEqual(bit_value(state['__known_ZMM'][0],512),(1<<128)-1)

    def test_source_mandatory_simd_prefix_context(self):
        self.model.step(self.decoder.decode(0,bytes.fromhex('660f6cc0')))
        state = self.state('ZMM')
        low = self.observed['xmm0'] & ((1<<64)-1)
        self.assertEqual(bit_value(state['ZMM'][0],512)&((1<<128)-1),low|(low<<64))

    def test_source_vector_preserves_unknown_upper_lanes(self):
        self.model.step(self.decoder.decode(0,bytes.fromhex('660fefc0')))
        state = self.state('ZMM','RIP')
        self.assertEqual(bit_value(state['ZMM'][0],512)&((1<<128)-1),0)
        self.assertEqual(bit_value(state['__known_ZMM'][0],512),(1<<128)-1)

    def test_source_load_lazy_inputs(self):
        self.model.step(self.decoder.decode(0,bytes.fromhex('488b07')))
        state = self.state('GPR','RIP')
        self.assertEqual(bit_value(state['GPR'][0],64),0x0706050403020100)
        self.assertEqual(self.model.memory,{0x2000+i:i for i in range(8)})

    def test_source_syscall_copies_undefined_flags_opaquely(self):
        self.model.step(self.decoder.decode(0,bytes.fromhex('31ff')))
        self.model.step(self.decoder.decode(2,bytes.fromhex('0f05')))
        state = self.state('RFLAGS','GPR','User_Syscall_Pre_RFLAGS','User_Environment_Cutpoint')
        mask = (1<<64)-1-16
        self.assertTrue(state['User_Environment_Cutpoint'])
        self.assertEqual(bit_value(state['__known_RFLAGS'],64),mask)
        self.assertEqual(bit_value(state['__known_User_Syscall_Pre_RFLAGS'],64),mask)
        self.assertEqual(bit_value(state['__known_GPR'][11],64),mask)
        self.assertEqual(bit_value(self.model.syscall_prestate['__known_RFLAGS'],64),mask)
        self.assertEqual((bit_value(state['GPR'][11],64)^bit_value(state['RFLAGS'],64))&mask,0)

    def test_source_syscall_cutpoint_without_apx_inputs(self):
        self.model.step(self.decoder.decode(0,bytes.fromhex('0f05')))
        state = self.state('User_Environment_Cutpoint','User_Syscall_Pre_GPR','GPR','Next_IP')
        self.assertTrue(state['User_Environment_Cutpoint'])
        self.assertEqual(bit_value(state['User_Syscall_Pre_GPR'][0],64),self.observed['rax'])
        self.assertEqual(bit_value(state['GPR'][1],64),2)
        self.assertEqual(bit_value(state['GPR'][11],64),0x202)

    def test_source_missing_byte_is_transactional(self):
        request = {'op':'eval','function':'User_Read.0','arguments':[8,bits(0x2000,64)],'include_state':False}
        response = self.oracle.request(request)
        self.assertFalse(response['ok'])
        self.assertEqual(response['error'],{'kind':'MissingMemory','address':'8192','access':'read'})
        self.assertEqual(int(self.state('User_Count')['User_Count']),0)
        self.model.supply(0x2000)
        self.assertEqual(bit_value(self.oracle.checked(request)['result'],8),0)


if __name__ == '__main__':
    unittest.main()
