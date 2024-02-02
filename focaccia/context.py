
class Context():
    def __init__(self, oracle: str, argv: list[str], emu: str) -> None:
        self.oracle = oracle
        self.argv = argv
        self.emu = emu