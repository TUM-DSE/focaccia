from snapshot import ProgramState, MemoryAccessError
from symbolic import SymbolicTransform

def _calc_transformation(previous: ProgramState, current: ProgramState):
    """Calculate the difference between two context blocks.

    :return: A context block that contains in its registers the difference
             between the corresponding input blocks' register values.
    """
    assert(previous.arch == current.arch)

    arch = previous.arch
    transformation = ProgramState(arch)
    for reg in arch.regnames:
        try:
            prev_val, cur_val = previous.read(reg), current.read(reg)
            if prev_val is not None and cur_val is not None:
                transformation.set(reg, cur_val - prev_val)
        except ValueError:
            # Register is not set in either state
            pass

    return transformation

def _find_errors(txl_state: ProgramState, prev_txl_state: ProgramState,
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

    transform_truth = _calc_transformation(prev_truth_state, truth_state)
    transform_txl = _calc_transformation(prev_txl_state, txl_state)
    for reg in arch.regnames:
        try:
            diff_txl = transform_txl.read(reg)
            diff_truth = transform_truth.read(reg)
        except ValueError:
            # Register is not set in either state
            continue

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
        'pc': test_states[0].read(PC_REGNAME),
        'txl': test_states[0], 'ref': truth_states[0],
        'errors': []
    }]

    it_prev = zip(iter(test_states), iter(truth_states))
    it_cur = zip(iter(test_states[1:]), iter(truth_states[1:]))

    for txl, truth in it_cur:
        prev_txl, prev_truth = next(it_prev)

        pc_txl = txl.read(PC_REGNAME)
        pc_truth = truth.read(PC_REGNAME)

        # The program counter should always be set on a snapshot
        assert(pc_truth is not None)
        assert(pc_txl is not None)

        if pc_txl != pc_truth:
            print(f'Unmatched program counter {hex(txl.read(PC_REGNAME))}'
                  f' in translated code!')
            continue

        errors = _find_errors(txl, prev_txl, truth, prev_truth)
        result.append({
            'pc': pc_txl,
            'txl': txl, 'ref': truth,
            'errors': errors
        })

        # TODO: Why do we skip backward branches?
        #if txl.has_backwards:
        #    print(f' -- Encountered backward branch. Don\'t skip.')

    return result

def _find_errors_symbolic(txl_from: ProgramState,
                          txl_to: ProgramState,
                          transform_truth: SymbolicTransform) \
        -> list[dict]:
    if (txl_from.read('PC') != transform_truth.range[0]) \
            or (txl_to.read('PC') != transform_truth.range[1]):
        tstart, tend = transform_truth.range
        print(f'[WARNING] Program counters of the tested state do not match'
              f' the truth state:'
              f' {hex(txl_from.read("PC"))} -> {hex(txl_to.read("PC"))} (test)'
              f' vs. {hex(tstart)} -> {hex(tend)} (truth).'
              f' Skipping with no errors.')
        return []

    errors = []

    # Calculate expected register values
    try:
        truth = transform_truth.calc_register_transform(txl_from)
    except MemoryAccessError:
        print(f'Transformation at {hex(transform_truth.addr)} depends on'
              f' memory, which is not available from arancini logs.'
              f' Skipping.')
        return errors

    # Compare expected values to actual values in the tested state
    for regname, truth_val in truth.items():
        try:
            txl_val = txl_to.read(regname)
        except ValueError:
            print(f'The tested state does not have a value for {regname}.'
                  ' Skipping.')
            continue
        except KeyError as err:
            print(err)
            continue

        if txl_val != truth_val:
            errors.append(f'Content of register {regname} is possibly false.' \
                          f' Expected value: {hex(truth_val)}, actual' \
                          f' value in the translation: {txl_val}.')

    return errors

def compare_symbolic(test_states: list[ProgramState],
                     transforms: list[SymbolicTransform]):
    #assert(len(test_states) == len(transforms) - 1)
    PC_REGNAME = 'PC'

    result = [{
        'pc': test_states[0].read(PC_REGNAME),
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

        start_addr, end_addr = transform.range
        if pc_cur != start_addr:
            print(f'Program counter {hex(pc_cur)} in translated code has no'
                  f' corresponding reference state! Skipping.'
                  f' (reference: {hex(start_addr)})')
            continue
        if pc_next != end_addr:
            print(f'Tested state transformation is {hex(pc_cur)} ->'
                  f' {hex(pc_next)}, but reference transform is'
                  f' {hex(start_addr)} -> {hex(end_addr)}!'
                  f' Skipping.')

        errors = _find_errors_symbolic(cur_state, next_state, transform)
        result.append({
            'pc': pc_cur,
            'txl': _calc_transformation(cur_state, next_state),
            'ref': transform,
            'errors': errors
        })

    return result
