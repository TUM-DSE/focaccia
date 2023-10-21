class Arch():
    def __init__(self, archname: str, regnames: list[str]):
        self.archname = archname
        self.regnames = set(regnames)

    def __eq__(self, other):
        return self.regnames == other.regnames
