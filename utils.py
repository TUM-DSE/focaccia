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

