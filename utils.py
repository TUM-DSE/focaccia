import sys
import shutil

def print_separator(separator: str = '-', stream=sys.stdout, count: int = 80):
    maxtermsize = count
    termsize = shutil.get_terminal_size((80, 20)).columns
    print(separator * min(termsize, maxtermsize), file=stream)

def check_version(version: str):
    # Script depends on ordered dicts in default dict()
    split = version.split('.')
    major = int(split[0])
    minor = int(split[1])
    if sys.version_info.major < major and sys.version_info.minor < minor:
        raise EnvironmentError("Expected at least Python 3.7")

def to_str(expr):
    """Convert a claripy expression to a nice string representation.

    Actually, the resulting representation is not very nice at all. It mostly
    serves debugging purposes.
    """
    import claripy

    if not issubclass(type(expr), claripy.ast.Base):
        return f'{type(expr)}[{str(expr)}]'

    assert(expr.depth > 0)
    if expr.depth == 1:
        if expr.symbolic:
            name = expr._encoded_name.decode()
            return f'symbol[{name}]'
        else:
            assert(expr.concrete)
            return f'value{expr.length}[{hex(expr.v)}]'

    args = [to_str(child) for child in expr.args]
    return f'expr[{str(expr.op)}({", ".join(args)})]'
