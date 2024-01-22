from functools import total_ordering
from typing import Iterable, Self

from .snapshot import ProgramState, MemoryAccessError, RegisterAccessError
from .symbolic import SymbolicTransform

@total_ordering
class ErrorSeverity:
    def __init__(self, num: int, name: str):
        """Construct an error severity.

        :param num:  A numerical value that orders the severity with respect
                     to other `ErrorSeverity` objects. Smaller values are less
                     severe.
        :param name: A descriptive name for the error severity, e.g. 'fatal'
                     or 'info'.
        """
        self._numeral = num
        self.name = name

    def __repr__(self) -> str:
        return f'[{self.name}]'

    def __eq__(self, other: Self) -> bool:
        return self._numeral == other._numeral

    def __lt__(self, other: Self) -> bool:
        return self._numeral < other._numeral

    def __hash__(self) -> int:
        return hash(self._numeral)

class ErrorTypes:
    INFO       = ErrorSeverity(0, 'INFO')
    INCOMPLETE = ErrorSeverity(2, 'INCOMPLETE DATA')
    POSSIBLE   = ErrorSeverity(4, 'UNCONFIRMED ERROR')
    CONFIRMED  = ErrorSeverity(5, 'ERROR')

class Error:
    """A state comparison error."""
    def __init__(self, severity: ErrorSeverity, msg: str):
        self.severity = severity
        self.error_msg = msg

    def __repr__(self) -> str:
        return f'{self.severity} {self.error_msg}'

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
            prev_val, cur_val = previous.read_register(reg), current.read_register(reg)
            if prev_val is not None and cur_val is not None:
                transformation.set_register(reg, cur_val - prev_val)
        except RegisterAccessError:
            # Register is not set in either state
            pass

    return transformation

def _find_errors(transform_txl: ProgramState, transform_truth: ProgramState) \
        -> list[Error]:
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
    assert(transform_truth.arch == transform_txl.arch)

    errors = []
    for reg in transform_truth.arch.regnames:
        try:
            diff_txl = transform_txl.read_register(reg)
            diff_truth = transform_truth.read_register(reg)
        except RegisterAccessError:
            errors.append(Error(ErrorTypes.INFO,
                                f'Unable to calculate difference:'
                                f' Value for register {reg} is not set in'
                                f' either the tested or the reference state.'))
            continue

        if diff_txl != diff_truth:
            errors.append(Error(
                ErrorTypes.CONFIRMED,
                f'Transformation of register {reg} is false.'
                f' Expected difference: {hex(diff_truth)},'
                f' actual difference in the translation: {hex(diff_txl)}.'))

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
        'pc': test_states[0].read_register(PC_REGNAME),
        'txl': test_states[0], 'ref': truth_states[0],
        'errors': []
    }]

    it_prev = zip(iter(test_states), iter(truth_states))
    it_cur = zip(iter(test_states[1:]), iter(truth_states[1:]))

    for txl, truth in it_cur:
        prev_txl, prev_truth = next(it_prev)

        pc_txl = txl.read_register(PC_REGNAME)
        pc_truth = truth.read_register(PC_REGNAME)

        # The program counter should always be set on a snapshot
        assert(pc_truth is not None)
        assert(pc_txl is not None)

        if pc_txl != pc_truth:
            print(f'Unmatched program counter {hex(txl.read_register(PC_REGNAME))}'
                  f' in translated code!')
            continue

        transform_truth = _calc_transformation(prev_truth, truth)
        transform_txl = _calc_transformation(prev_txl, txl)
        errors = _find_errors(transform_txl, transform_truth)
        result.append({
            'pc': pc_txl,
            'txl': transform_txl, 'ref': transform_truth,
            'errors': errors
        })

    return result

def _find_register_errors(txl_from: ProgramState,
                          txl_to: ProgramState,
                          transform_truth: SymbolicTransform) \
        -> list[Error]:
    """Find errors in register values.

    Errors might be:
     - A register value was modified, but the tested state contains no
       reference value for that register.
     - The tested destination state's value for a register does not match
       the value expected by the symbolic transformation.
    """
    # Calculate expected register values
    try:
        truth = transform_truth.eval_register_transforms(txl_from)
    except MemoryAccessError as err:
        s, e = transform_truth.range
        return [Error(
            ErrorTypes.INCOMPLETE,
            f'Register transformations {hex(s)} -> {hex(e)} depend on'
            f' {err.mem_size} bytes at memory address {hex(err.mem_addr)}'
            f' that are not entirely present in the tested state'
            f' {hex(txl_from.read_register("pc"))}.',
        )]
    except RegisterAccessError as err:
        s, e = transform_truth.range
        return [Error(ErrorTypes.INCOMPLETE,
                      f'Register transformations {hex(s)} -> {hex(e)} depend'
                      f' on the value of register {err.regname}, which is not'
                      f' set in the tested state.')]

    # Compare expected values to actual values in the tested state
    errors = []
    for regname, truth_val in truth.items():
        try:
            txl_val = txl_to.read_register(regname)
        except RegisterAccessError:
            errors.append(Error(ErrorTypes.INCOMPLETE,
                                f'Value of register {regname} has changed, but'
                                f' is not set in the tested state.'))
            continue
        except KeyError as err:
            print(f'[WARNING] {err}')
            continue

        if txl_val != truth_val:
            errors.append(Error(ErrorTypes.CONFIRMED,
                                f'Content of register {regname} is false.'
                                f' Expected value: {hex(truth_val)}, actual'
                                f' value in the translation: {hex(txl_val)}.'))
    return errors

def _find_memory_errors(txl_from: ProgramState,
                        txl_to: ProgramState,
                        transform_truth: SymbolicTransform) \
        -> list[Error]:
    """Find errors in memory values.

    Errors might be:
     - A range of memory was written, but the tested state contains no
       reference value for that range.
     - The tested destination state's content for the tested range does not
       match the value expected by the symbolic transformation.
    """
    # Calculate expected register values
    try:
        truth = transform_truth.eval_memory_transforms(txl_from)
    except MemoryAccessError as err:
        s, e = transform_truth.range
        return [Error(ErrorTypes.INCOMPLETE,
                      f'Memory transformations {hex(s)} -> {hex(e)} depend on'
                      f' {err.mem_size} bytes at memory address {hex(err.mem_addr)}'
                      f' that are not entirely present in the tested state at'
                      f' {hex(txl_from.read_register("pc"))}.')]
    except RegisterAccessError as err:
        s, e = transform_truth.range
        return [Error(ErrorTypes.INCOMPLETE,
                      f'Memory transformations {hex(s)} -> {hex(e)} depend on'
                      f' the value of register {err.regname}, which is not'
                      f' set in the tested state.')]

    # Compare expected values to actual values in the tested state
    errors = []
    for addr, truth_bytes in truth.items():
        size = len(truth_bytes)
        try:
            txl_bytes = txl_to.read_memory(addr, size)
        except MemoryAccessError:
            errors.append(Error(ErrorTypes.POSSIBLE,
                                f'Memory range [{hex(addr)}, {hex(addr + size)})'
                                f' is not set in the tested result state at'
                                f' {hex(txl_to.read_register("pc"))}. This is'
                                f' either an error in the translation or'
                                f' the recorded test state is missing data.'))
            continue

        if txl_bytes != truth_bytes:
            errors.append(Error(ErrorTypes.CONFIRMED,
                                f'Content of memory at {hex(addr)} is false.'
                                f' Expected content: {truth_bytes.hex()},'
                                f' actual content in the translation:'
                                f' {txl_bytes.hex()}.'))
    return errors

def _find_errors_symbolic(txl_from: ProgramState,
                          txl_to: ProgramState,
                          transform_truth: SymbolicTransform) \
        -> list[Error]:
    """Tries to find errors in transformations between tested states.

    Applies a transformation to a source state and tests whether the result
    matches a given destination state.

    :param txl_from:        Source state. This is a state from the tested
                            program, and is assumed as the starting point for
                            the transformation.
    :param txl_to:          Destination state. This is a possibly faulty state
                            from the tested program, and is tested for
                            correctness with respect to the source state.
    :param transform_truth: The symbolic transformation that maps the source
                            state to the destination state.
    """
    if (txl_from.read_register('PC') != transform_truth.range[0]) \
            or (txl_to.read_register('PC') != transform_truth.range[1]):
        tstart, tend = transform_truth.range
        return [Error(ErrorTypes.POSSIBLE,
                      f'Program counters of the tested transformation'
                      f' do not match the truth transformation:'
                      f' {hex(txl_from.read_register("PC"))} -> {hex(txl_to.read_register("PC"))}'
                      f' (test) vs. {hex(tstart)} -> {hex(tend)} (truth).'
                      f' Skipping with no errors.')]

    errors = []
    errors.extend(_find_register_errors(txl_from, txl_to, transform_truth))
    errors.extend(_find_memory_errors(txl_from, txl_to, transform_truth))

    return errors

def compare_symbolic(test_states: Iterable[ProgramState],
                     transforms: Iterable[SymbolicTransform]) \
        -> list[dict]:
    test_states = iter(test_states)
    transforms = iter(transforms)

    result = []
    cur_state = next(test_states)   # The state before the transformation
    transform = next(transforms)    # Operates on `cur_state`

    while True:
        try:
            next_state = next(test_states) # The state after the transformation

            pc_cur = cur_state.read_register('PC')
            pc_next = next_state.read_register('PC')
            start_addr, end_addr = transform.range
            if pc_cur != start_addr:
                print(f'Program counter {hex(pc_cur)} in translated code has'
                      f' no corresponding reference state! Skipping.'
                      f' (reference: {hex(start_addr)})')
                cur_state = next_state
                transform = next(transforms)
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

            # Step forward
            cur_state = next_state
            transform = next(transforms)
        except StopIteration:
            break

    return result
