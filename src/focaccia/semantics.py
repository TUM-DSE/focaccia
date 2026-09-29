"""Instruction semantic backend interface and the default Miasm implementation."""

from __future__ import annotations

from typing import Protocol

from miasm.expression.expression import Expr, ExprInt

from focaccia.miasm_util import MiasmSymbolResolver
from focaccia.snapshot import ReadableProgramState
from focaccia.symbolic import DisassemblyContext, Instruction, run_instruction


class InstructionSemanticsBackend(Protocol):
    """Generate a symbolic transition for a decoded instruction."""

    name: str

    def generate(
        self,
        instruction: Instruction,
        state: ReadableProgramState,
        context: DisassemblyContext,
    ) -> tuple[ExprInt | None, dict[Expr, Expr]]: ...


class MiasmBackend:
    """Adapter preserving Focaccia's existing Miasm execution path."""

    name = "miasm"

    def generate(
        self,
        instruction: Instruction,
        state: ReadableProgramState,
        context: DisassemblyContext,
    ) -> tuple[ExprInt | None, dict[Expr, Expr]]:
        return run_instruction(
            instruction.instr,
            MiasmSymbolResolver(state, context.loc_db),
            context.lifter,
        )
