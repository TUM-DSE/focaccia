from snapshot import ProgramState
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

def equivalent(val1, val2, transformation, previous_translation):
    if val1 == val2:
        return True

    # TODO: maybe incorrect
    return val1 - previous_translation == transformation

def verify(translation: ProgramState, reference: ProgramState,
           transformation: ProgramState, previous_translation: ProgramState):
    assert(translation.arch == reference.arch)

    if translation.regs["PC"] != reference.regs["PC"]:
        return 1

    print_separator()
    print(f'For PC={translation.as_repr("PC")}')
    print_separator()
    for reg in translation.arch.regnames:
        if translation.regs[reg] is None:
            print(f'Element not available in translation: {reg}')
        elif reference.regs[reg] is None:
            print(f'Element not available in reference: {reg}')
        elif not equivalent(translation.regs[reg], reference.regs[reg],
                            transformation.regs[reg],
                            previous_translation.regs[reg]):
            txl = translation.as_repr(reg)
            ref = reference.as_repr(reg)
            print(f'Difference for {reg}: {txl} != {ref}')

    return 0

def compare(txl: list[ProgramState],
            native: list[ProgramState],
            progressive: bool = False,
            stats: bool = False):
    """Compare two lists of snapshots and output the differences.

    :param txl: The translated, and possibly faulty, state of the program.
    :param native: The 'correct' reference state of the program.
    :param progressive:
    :param stats:
    """

    if len(txl) != len(native):
        print(f'Different numbers of blocks discovered: '
              f'{len(txl)} in translation vs. {len(native)} in reference.')

    previous_reference = native[0]
    previous_translation = txl[0]

    unmatched_pcs = {}
    pc_to_skip = ""
    if progressive:
        i = 0
        for translation in txl:
            previous = i

            while i < len(native):
                reference = native[i]
                transformation = calc_transformation(previous_reference, reference)
                if verify(translation, reference, transformation, previous_translation) == 0:
                    reference.matched = True
                    break

                i += 1

            matched = True

            # Didn't find anything
            if i == len(native):
                matched = False
                # TODO: add verbose output
                print_separator()
                print(f'No match for PC {hex(translation.regs["PC"])}')
                if translation.regs['PC'] not in unmatched_pcs:
                    unmatched_pcs[translation.regs['PC']] = 0
                unmatched_pcs[translation.regs['PC']] += 1

                i = previous

            # Necessary since we may have run out of native BBs to check and
            # previous becomes len(native)
            #
            # We continue checking to report unmatched translation PCs
            if i < len(native):
                previous_reference = native[i]

            previous_translation = translation

            # Skip next reference when there is a backwards branch
            # NOTE: if a reference was skipped, don't skip it again
            #       necessary for loops which may have multiple backwards
            #       branches
            if translation.has_backwards and translation.regs['PC'] != pc_to_skip:
                pc_to_skip = translation.regs['PC']
                i += 1

            if matched:
                i += 1
    else:
        txl = iter(txl)
        native = iter(native)
        for translation, reference in zip(txl, native):
            transformation = calc_transformation(previous_reference, reference)
            if verify(translation, reference, transformation, previous_translation) == 1:
                # TODO: add verbose output
                print_separator()
                print(f'No match for PC {hex(translation.regs["PC"])}')
                if translation.regs['PC'] not in unmatched_pcs:
                    unmatched_pcs[translation.regs['PC']] = 0
                unmatched_pcs[translation.regs['PC']] += 1
            else:
                reference.matched = True

            if translation.has_backwards:
                next(native)

            previous_reference = reference
            previous_translation = translation

    if stats:
        print_separator()
        print('Statistics:')
        print_separator()

        for pc in unmatched_pcs:
            print(f'PC {hex(pc)} unmatched {unmatched_pcs[pc]} times')

        # NOTE: currently doesn't handle mismatched due backward branches
        current = ""
        unmatched_count = 0
        for ref in native:
            ref_pc = ref.regs['PC']
            if ref_pc != current:
                if unmatched_count:
                    print(f'Reference PC {hex(current)} unmatched {unmatched_count} times')
                current = ref_pc

            if ref.matched == False:
                unmatched_count += 1
    return 0
