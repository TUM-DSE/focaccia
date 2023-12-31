import sys
import shutil

def print_separator(separator: str = '-', stream=sys.stdout, count: int = 80):
    maxtermsize = count
    termsize = shutil.get_terminal_size((80, 20)).columns
    print(separator * min(termsize, maxtermsize), file=stream)
