import ast
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYTHON_SOURCES = (
    *sorted((PROJECT_ROOT / "src" / "focaccia").rglob("*.py")),
    *sorted((PROJECT_ROOT / "tests").rglob("*.py")),
)


def _calls_named(name: str) -> list[str]:
    callers = []
    for path in PYTHON_SOURCES:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if isinstance(function, ast.Name) and function.id == name:
                callers.append(f"{path.relative_to(PROJECT_ROOT)}:{node.lineno}")
            elif isinstance(function, ast.Attribute) and function.attr == name:
                callers.append(f"{path.relative_to(PROJECT_ROOT)}:{node.lineno}")
    return callers


def test_set_register_migration_is_complete():
    assert _calls_named("set_register") == []


def test_clients_do_not_construct_lldb_concrete_target():
    assert _calls_named("LLDBConcreteTarget") == []


def test_trace_contract_migration_has_no_ambiguous_or_private_accesses():
    forbidden = []
    trace_module = PROJECT_ROOT / "src" / "focaccia" / "trace.py"
    for path in PYTHON_SOURCES:
        if path == trace_module:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "_iter",
                "_state_list",
                "states",
            }:
                forbidden.append(
                    f"{path.relative_to(PROJECT_ROOT)}:{node.lineno}:{node.attr}"
                )
    assert forbidden == []
