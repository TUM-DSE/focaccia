from snapshot import ProgramState, SnapshotSymbolResolver
from symbolic import SymbolicTransform
from utils import print_separator

def calc_transformation(previous: ProgramState, current: ProgramState):
    """Calculate the difference between two context blocks.

    :return: A context block that contains in its registers the difference
             between the corresponding input blocks' register values.
    """
    assert(previous.arch == current.arch)

    arch = previous.arch
    transformation = ProgramState(arch)
    for reg in arch.regnames:
        prev_val, cur_val = previous.regs[reg], current.regs[reg]
        if prev_val is not None and cur_val is not None:
            transformation.regs[reg] = cur_val - prev_val

    return transformation

def find_errors(txl_state: ProgramState, prev_txl_state: ProgramState,
                truth_state: ProgramState, prev_truth_state: ProgramState) \
        -> list[dict]:
    """Find possible errors between a reference and a tested state.

    :param txl_state: The translated state to check for errors.
    :param prev_txl_state: The translated snapshot immediately preceding
                           `txl_state`.
    :param truth_state: The reference state against which to check the
                        translated state `txl_state` for errors.
    :param prev_truth_state: The reference snapshot immediately preceding
                           `prev_truth_state`.

    :return: A list of errors; one entry for each register that may have
             faulty contents. Is empty if no errors were found.
    """
    arch = txl_state.arch
    errors = []

    transform_truth = calc_transformation(prev_truth_state, truth_state)
    transform_txl = calc_transformation(prev_txl_state, txl_state)
    for reg in arch.regnames:
        diff_txl = transform_txl.regs[reg]
        diff_truth = transform_truth.regs[reg]
        if diff_txl == diff_truth:
            # The register contains a value that is expected
            # by the transformation.
            continue
        if diff_truth is not None:
            if diff_txl is None:
                print(f'[WARNING] Expected the value of register {reg} to be'
                      f' defined, but it is undefined in the translation.'
                      f' This might hint at an error in the input data.')
            else:
                errors.append({
                    'reg': reg,
                    'expected': diff_truth, 'actual': diff_txl,
                })

    return errors

def compare_simple(test_states: list[ProgramState],
                   truth_states: list[ProgramState]) -> list[dict]:
    """Simple comparison of programs.

    :param test_states: A program flow to check for errors.
    :param truth_states: A reference program flow that defines a correct
                         program execution.

    :return: Information, including possible errors, about each processed
             snapshot.
    """
    PC_REGNAME = 'PC'

    if len(test_states) == 0:
        print('No states to compare. Exiting.')
        return []

    # No errors in initial snapshot because we can't perform difference
    # calculations on it
    result = [{
        'pc': test_states[0].regs[PC_REGNAME],
        'txl': test_states[0], 'ref': truth_states[0],
        'errors': []
    }]

    it_prev = zip(iter(test_states), iter(truth_states))
    it_cur = zip(iter(test_states[1:]), iter(truth_states[1:]))

    for txl, truth in it_cur:
        prev_txl, prev_truth = next(it_prev)

        pc_txl = txl.regs[PC_REGNAME]
        pc_truth = truth.regs[PC_REGNAME]

        # The program counter should always be set on a snapshot
        assert(pc_truth is not None)
        assert(pc_txl is not None)

        if pc_txl != pc_truth:
            print(f'Unmatched program counter {txl.as_repr(PC_REGNAME)}'
                  f' in translated code!')
            continue
        else:
            txl.matched = True

        errors = find_errors(txl, prev_txl, truth, prev_truth)
        result.append({
            'pc': pc_txl,
            'txl': txl, 'ref': truth,
            'errors': errors
        })

        # TODO: Why do we skip backward branches?
        if txl.has_backwards:
            print(f' -- Encountered backward branch. Don\'t skip.')

    return result

def find_errors_symbolic(txl_from: ProgramState,
                         txl_to: ProgramState,
                         transform_truth: SymbolicTransform) \
        -> list[dict]:
    arch = txl_from.arch
    resolver = SnapshotSymbolResolver(txl_from)

    assert(txl_from.read('PC') == transform_truth.start_addr)
    assert(txl_to.read('PC') == transform_truth.end_addr)

    errors = []
    for reg in arch.regnames:
        if txl_from.read(reg) is None or txl_to.read(reg) is None:
            print(f'A value for {reg} must be set in all translated states.'
                  ' Skipping.')
            continue

        txl_val = txl_to.read(reg)
        try:
            truth = transform_truth.eval_register_transform(reg.lower(), resolver)
            print(f'Evaluated symbolic formula to {hex(txl_val)} vs. txl {hex(txl_val)}')
            if txl_val != truth:
                errors.append({
                    'reg': reg,
                    'expected': truth,
                    'actual': txl_val,
                    'equation': transform_truth.state.regs.get(reg),
                })
        except AttributeError:
            print(f'Register {reg} does not exist.')

    return errors

def compare_symbolic(test_states: list[ProgramState],
                     transforms: list[SymbolicTransform]):
    #assert(len(test_states) == len(transforms) - 1)
    PC_REGNAME = 'PC'

    result = [{
        'pc': test_states[0].regs[PC_REGNAME],
        'txl': test_states[0],
        'ref': transforms[0],
        'errors': []
    }]

    _list = zip(test_states[:-1], test_states[1:], transforms)
    for cur_state, next_state, transform in _list:
        pc_cur = cur_state.read(PC_REGNAME)
        pc_next = next_state.read(PC_REGNAME)

        # The program counter should always be set on a snapshot
        assert(pc_cur is not None and pc_next is not None)

        if pc_cur != transform.start_addr:
            print(f'Program counter {hex(pc_cur)} in translated code has no'
                  f' corresponding reference state! Skipping.'
                  f' (reference: {hex(transform.start_addr)})')
            continue
        if pc_next != transform.end_addr:
            print(f'Tested state transformation is {hex(pc_cur)} ->'
                  f' {hex(pc_next)}, but reference transform is'
                  f' {hex(transform.start_addr)} -> {hex(transform.end_addr)}!'
                  f' Skipping.')

        errors = find_errors_symbolic(cur_state, next_state, transform)
        result.append({
            'pc': pc_cur,
            'txl': calc_transformation(cur_state, next_state),
            'ref': transform,
            'errors': errors
        })

    return result
