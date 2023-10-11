class Arch():
    def __init__(self, regnames: list[str]):
        self.regnames = regnames

    def __eq__(self, other):
        return self.regnames == other.regnames
