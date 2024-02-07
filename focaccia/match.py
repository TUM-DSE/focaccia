from typing import Iterable

from .snapshot import ProgramState
from .symbolic import SymbolicTransform

def _find_index(seq: Iterable, target, access_seq_elem=lambda el: el):
    for i, el in enumerate(seq):
        if access_seq_elem(el) == target:
            return i
    return None

def fold_traces(ctrace: list[ProgramState],
                strace: list[SymbolicTransform]):
    """Try to fold a higher-granularity symbolic trace to match a lower-
    granularity concrete trace.

    Modifies the inputs in-place.

    :param ctrace: A concrete trace. Is assumed to have lower granularity than
                   `truth`.
    :param strace: A symbolic trace. Is assumed to have higher granularity than
                   `test`. We assume that because we control the symbolic trace
                   generation algorithm, and it produces traces on the level of
                   single instructions, which is the highest granularity
                   possible.
    """
    if not ctrace or not strace:
        return [], []

    assert(ctrace[0].read_register('pc') == strace[0].addr)

    i = 0
    for next_state in ctrace[1:]:
        next_pc = next_state.read_register('pc')
        index_in_truth = _find_index(strace[i:], next_pc, lambda el: el.range[1])

        # If no next element (i.e. no foldable range) is found in the truth
        # trace, assume that the test trace contains excess states. Remove one
        # and try again. This might skip testing some states, but covers more
        # of the entire trace.
        if index_in_truth is None:
            ctrace.pop(i + 1)
            continue

        # Fold the range of truth states until the next test state
        for _ in range(index_in_truth):
            strace[i].concat(strace.pop(i + 1))

        i += 1
        if len(strace) <= i:
            break

    # Fold remaining symbolic transforms into one
    while i + 1 < len(strace):
        strace[i].concat(strace.pop(i + 1))

def match_traces(ctrace: list[ProgramState], \
                 strace: list[SymbolicTransform]):
    """Try to match traces that don't follow the same program flow.

    This algorithm is useful if traces of the same binary mismatch due to
    differences in environment during their recording.

    Does not modify the arguments. Creates and returns new lists.

    :param test: A concrete trace.
    :param truth: A symbolic trace.

    :return: The modified traces.
    """
    if not strace:
        return [], []

    states = []
    matched_transforms = []

    state_iter = iter(ctrace)
    symb_i = 0
    for cur_state in state_iter:
        pc = cur_state.read_register('pc')

        if pc != strace[symb_i].addr:
            next_i = _find_index(strace[symb_i+1:], pc, lambda t: t.addr)

            # Drop the concrete state if no address in the symbolic trace
            # matches
            if next_i is None:
                continue

            # Otherwise, jump to the next matching symbolic state
            symb_i += next_i + 1

        # Append the now matching state/transform pair to the traces
        assert(cur_state.read_register('pc') == strace[symb_i].addr)
        states.append(cur_state)
        matched_transforms.append(strace[symb_i])

        # Step forward
        symb_i += 1

    assert(len(states) == len(matched_transforms))

    return states, matched_transforms
