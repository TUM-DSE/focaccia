"""Check `nix derivation show --recursive` output without realizing build inputs."""
import json
import sys

# Nix 2.34 wraps the older derivation map in a versioned envelope.
document = json.load(sys.stdin)
derivations = document.get("derivations", document)
if not isinstance(derivations, dict) or not derivations:
    raise SystemExit("Expected a nonempty derivation graph")

prefixes = (
    "focaccia-tir-", "tiramisu-", "tirrt-", "tir-core-",
    "armv8-a-asl-spec-", "asl-parser-",
)
forbidden = []
for path, derivation in derivations.items():
    name = derivation.get("name", derivation.get("env", {}).get("name", ""))
    if not name:
        raise SystemExit(f"Missing derivation name: {path}")
    if name.startswith(prefixes):
        forbidden.append(path)
if forbidden:
    raise SystemExit("TIR in default build graph:\n" + "\n".join(sorted(forbidden)))
print(f"Default build graph: {len(derivations)} derivations, no TIR artifacts")
