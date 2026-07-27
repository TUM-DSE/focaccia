"""Versioned identities for RR-to-QEMU integration runs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from focaccia.arch.arch import ArchitectureKey
from focaccia.deterministic import DeterministicLog
from focaccia.trace import TraceEnvironment
from focaccia.utils import file_hash


REPLAY_RUN_MANIFEST_SCHEMA = "focaccia-rr-qemu-run-v1"


class ReplayManifestError(ValueError):
    """A replay-run manifest is malformed or disagrees with its artifacts."""


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
    """Content identity of one named run artifact."""

    name: str
    sha256: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("An artifact identity requires a name.")
        if len(self.sha256) != 64:
            raise ValueError(f"Artifact {self.name!r} has an invalid SHA-256 digest.")
        try:
            int(self.sha256, 16)
        except ValueError as error:
            raise ValueError(
                f"Artifact {self.name!r} has a non-hexadecimal SHA-256 digest."
            ) from error

    def to_json(self) -> dict[str, str]:
        return {"name": self.name, "sha256": self.sha256}

    @classmethod
    def from_json(cls, document: object, *, context: str) -> ArtifactIdentity:
        if not isinstance(document, dict):
            raise ReplayManifestError(f"{context} must be an object.")
        if set(document) != {"name", "sha256"}:
            raise ReplayManifestError(f"{context} contains unknown or missing fields.")
        name = document.get("name")
        digest = document.get("sha256")
        if not isinstance(name, str) or not isinstance(digest, str):
            raise ReplayManifestError(f"{context} requires string name and sha256 fields.")
        try:
            return cls(name, digest)
        except ValueError as error:
            raise ReplayManifestError(f"{context}: {error}") from error


@dataclass(frozen=True, slots=True)
class ReplayRunManifest:
    """Identity binding for one native-oracle/QEMU-consumer smoke run."""

    guest_architecture: ArchitectureKey
    binary: ArtifactIdentity
    inputs: tuple[ArtifactIdentity, ...]
    argv: tuple[str, ...]
    start_address: int | None
    stop_address: int | None
    oracle: ArtifactIdentity
    rr_directory_sha256: str
    rr_trace_version: int
    rr_schema_version: str
    rr_schema_id: str
    rr_trace_uuid: str
    rr_native_architecture: ArchitectureKey

    def __post_init__(self) -> None:
        if self.binary.name != "guest-binary":
            raise ValueError("Replay-run binary identity has the wrong logical name.")
        if self.oracle.name != "symbolic-oracle":
            raise ValueError("Replay-run oracle identity has the wrong logical name.")
        if len({item.name for item in self.inputs}) != len(self.inputs):
            raise ValueError("Replay-run input names must be unique.")
        if len(self.rr_directory_sha256) != 64:
            raise ValueError("The RR directory SHA-256 digest is invalid.")
        try:
            int(self.rr_directory_sha256, 16)
        except ValueError as error:
            raise ValueError("The RR directory SHA-256 digest is not hexadecimal.") from error
        if len(self.rr_trace_uuid) != 32:
            raise ValueError("The RR trace UUID must contain 16 bytes of hexadecimal data.")
        try:
            int(self.rr_trace_uuid, 16)
        except ValueError as error:
            raise ValueError("The RR trace UUID is not hexadecimal.") from error
        for label, address in (
            ("start", self.start_address),
            ("stop", self.stop_address),
        ):
            if address is not None and address < 0:
                raise ValueError(f"The replay {label} address cannot be negative.")
        if (
            self.start_address is not None
            and self.stop_address is not None
            and self.stop_address < self.start_address
        ):
            raise ValueError("The replay stop address cannot precede its start address.")
        if self.rr_trace_version <= 0:
            raise ValueError("The RR trace version must be positive.")
        if not self.rr_schema_version or not self.rr_schema_id:
            raise ValueError("The RR schema version and ID cannot be empty.")

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": REPLAY_RUN_MANIFEST_SCHEMA,
            "guest_architecture": _architecture_to_json(self.guest_architecture),
            "binary": self.binary.to_json(),
            "inputs": [item.to_json() for item in self.inputs],
            "argv": list(self.argv),
            "start_address": self.start_address,
            "stop_address": self.stop_address,
            "oracle": self.oracle.to_json(),
            "rr": {
                "directory_sha256": self.rr_directory_sha256,
                "trace_version": self.rr_trace_version,
                "schema_version": self.rr_schema_version,
                "schema_id": self.rr_schema_id,
                "trace_uuid": self.rr_trace_uuid,
                "native_architecture": _architecture_to_json(self.rr_native_architecture),
            },
        }

    @classmethod
    def from_json(cls, document: object) -> ReplayRunManifest:
        if not isinstance(document, dict):
            raise ReplayManifestError("Replay-run manifest must be an object.")
        if document.get("schema") != REPLAY_RUN_MANIFEST_SCHEMA:
            raise ReplayManifestError(
                f"Unsupported replay-run manifest schema {document.get('schema')!r}."
            )
        expected_fields = {
            "schema",
            "guest_architecture",
            "binary",
            "inputs",
            "argv",
            "start_address",
            "stop_address",
            "oracle",
            "rr",
        }
        if set(document) != expected_fields:
            raise ReplayManifestError("Replay-run manifest contains unknown or missing fields.")
        argv = document.get("argv")
        inputs = document.get("inputs")
        rr = document.get("rr")
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            raise ReplayManifestError("Replay-run argv must be a string list.")
        if not isinstance(inputs, list):
            raise ReplayManifestError("Replay-run inputs must be a list.")
        if not isinstance(rr, dict):
            raise ReplayManifestError("Replay-run rr field must be an object.")
        if set(rr) != {
            "directory_sha256",
            "trace_version",
            "schema_version",
            "schema_id",
            "trace_uuid",
            "native_architecture",
        }:
            raise ReplayManifestError("Replay-run rr field contains unknown or missing fields.")
        start_address = _optional_non_negative_int(document.get("start_address"), "start_address")
        stop_address = _optional_non_negative_int(document.get("stop_address"), "stop_address")
        try:
            return cls(
                _architecture_from_json(document.get("guest_architecture"), "guest_architecture"),
                ArtifactIdentity.from_json(document.get("binary"), context="binary"),
                tuple(
                    ArtifactIdentity.from_json(item, context=f"inputs[{index}]")
                    for index, item in enumerate(inputs)
                ),
                tuple(argv),
                start_address,
                stop_address,
                ArtifactIdentity.from_json(document.get("oracle"), context="oracle"),
                _required_string(rr, "directory_sha256", "rr"),
                _required_int(rr, "trace_version", "rr"),
                _required_string(rr, "schema_version", "rr"),
                _required_string(rr, "schema_id", "rr"),
                _required_string(rr, "trace_uuid", "rr"),
                _architecture_from_json(rr.get("native_architecture"), "rr.native_architecture"),
            )
        except ValueError as error:
            if isinstance(error, ReplayManifestError):
                raise
            raise ReplayManifestError(str(error)) from error


def _required_string(document: Mapping[str, object], name: str, context: str) -> str:
    value = document.get(name)
    if not isinstance(value, str):
        raise ReplayManifestError(f"{context}.{name} must be a string.")
    return value


def _required_int(document: Mapping[str, object], name: str, context: str) -> int:
    value = document.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ReplayManifestError(f"{context}.{name} must be an integer.")
    return value


def _optional_non_negative_int(value: object, context: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReplayManifestError(f"{context} must be a non-negative integer or null.")
    return value


def _architecture_to_json(architecture: ArchitectureKey) -> dict[str, str]:
    return {"isa": architecture.isa, "endianness": architecture.endianness}


def _architecture_from_json(document: object, context: str) -> ArchitectureKey:
    if not isinstance(document, dict):
        raise ReplayManifestError(f"{context} must be an architecture object.")
    if set(document) != {"isa", "endianness"}:
        raise ReplayManifestError(f"{context} contains unknown or missing fields.")
    isa = document.get("isa")
    endianness = document.get("endianness")
    if not isinstance(isa, str) or endianness not in ("little", "big"):
        raise ReplayManifestError(f"{context} contains an invalid architecture.")
    return ArchitectureKey(isa, endianness)


def rr_directory_hash(directory: str | Path) -> str:
    """Hash one RR directory by relative names, file bytes, and symlink targets."""
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ReplayManifestError(f"RR trace directory does not exist: {root}.")
    digest = hashlib.sha256()
    entries = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    for path in entries:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        if path.is_symlink():
            try:
                path.resolve(strict=True).relative_to(root)
            except (OSError, ValueError) as error:
                raise ReplayManifestError(
                    f"RR trace symlink escapes the trace directory or is broken: {path}."
                ) from error
            kind = b"L"
            payload = str(path.readlink()).encode("utf-8")
            payload_size = len(payload)
        elif path.is_file():
            kind = b"F"
            before = path.stat()
            payload = None
            payload_size = before.st_size
        elif path.is_dir():
            kind = b"D"
            payload = b""
            payload_size = 0
        else:
            raise ReplayManifestError(f"Unsupported RR trace entry type: {path}.")
        digest.update(kind)
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(payload_size.to_bytes(8, "big"))
        if payload is not None:
            digest.update(payload)
            continue
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ReplayManifestError(f"RR trace entry changed while hashing: {path}.")
    return digest.hexdigest()


def create_replay_run_manifest(
    *,
    binary_path: str | Path,
    input_paths: Mapping[str, str | Path],
    argv: Sequence[str],
    oracle_path: str | Path,
    trace_environment: TraceEnvironment,
    deterministic_log: DeterministicLog,
) -> ReplayRunManifest:
    """Create and internally validate a manifest from realized run artifacts."""
    metadata = deterministic_log.metadata
    base_directory = deterministic_log.base_directory
    if metadata is None or base_directory is None:
        raise ReplayManifestError("A replay-run manifest requires a non-empty RR log.")
    if trace_environment.architecture is None:
        raise ReplayManifestError("The oracle trace has no guest architecture identity.")
    binary = ArtifactIdentity("guest-binary", file_hash(binary_path))
    inputs = tuple(
        ArtifactIdentity(name, file_hash(path)) for name, path in sorted(input_paths.items())
    )
    oracle = ArtifactIdentity("symbolic-oracle", file_hash(oracle_path))
    manifest = ReplayRunManifest(
        trace_environment.architecture,
        binary,
        inputs,
        tuple(argv),
        trace_environment.start_address,
        trace_environment.stop_address,
        oracle,
        rr_directory_hash(base_directory),
        metadata.trace_version,
        metadata.schema_version,
        metadata.schema_id,
        metadata.trace_uuid.hex(),
        metadata.native_architecture.key,
    )
    validate_replay_run_manifest(
        manifest,
        binary_path=binary_path,
        input_paths=input_paths,
        argv=argv,
        oracle_path=oracle_path,
        trace_environment=trace_environment,
        deterministic_log=deterministic_log,
    )
    return manifest


def validate_replay_run_manifest(
    manifest: ReplayRunManifest,
    *,
    binary_path: str | Path,
    input_paths: Mapping[str, str | Path],
    argv: Sequence[str],
    oracle_path: str | Path,
    trace_environment: TraceEnvironment,
    deterministic_log: DeterministicLog,
) -> None:
    """Reject any producer/consumer identity mismatch before QEMU mutation."""
    mismatches: list[str] = []
    metadata = deterministic_log.metadata
    base_directory = deterministic_log.base_directory
    actual_binary_hash = file_hash(binary_path)
    if manifest.binary.sha256 != actual_binary_hash:
        mismatches.append("guest binary hash")
    if trace_environment.binary_hash != actual_binary_hash:
        mismatches.append("oracle environment binary hash")
    if tuple(argv) != manifest.argv or trace_environment.argv != tuple(argv):
        mismatches.append("guest arguments")
    if trace_environment.architecture != manifest.guest_architecture:
        mismatches.append("guest architecture")
    if trace_environment.start_address != manifest.start_address:
        mismatches.append("trace start address")
    if trace_environment.stop_address != manifest.stop_address:
        mismatches.append("trace stop address")
    if manifest.oracle.sha256 != file_hash(oracle_path):
        mismatches.append("symbolic oracle hash")

    actual_inputs = {name: file_hash(path) for name, path in sorted(input_paths.items())}
    expected_inputs = {item.name: item.sha256 for item in manifest.inputs}
    if actual_inputs != expected_inputs:
        mismatches.append("input file identities")

    if metadata is None or base_directory is None:
        mismatches.append("RR log presence")
    else:
        if manifest.rr_directory_sha256 != rr_directory_hash(base_directory):
            mismatches.append("RR directory hash")
        provenance = trace_environment.replay_provenance
        if provenance is None or Path(provenance).resolve() != base_directory.resolve():
            mismatches.append("oracle RR provenance")
        if manifest.rr_trace_version != metadata.trace_version:
            mismatches.append("RR trace version")
        if manifest.rr_schema_version != metadata.schema_version:
            mismatches.append("RR schema version")
        if manifest.rr_schema_id != metadata.schema_id:
            mismatches.append("RR schema ID")
        if manifest.rr_trace_uuid != metadata.trace_uuid.hex():
            mismatches.append("RR trace UUID")
        if manifest.rr_native_architecture != metadata.native_architecture.key:
            mismatches.append("RR native architecture")
        if manifest.guest_architecture != metadata.native_architecture.key:
            mismatches.append("oracle/RR architecture")

    if mismatches:
        raise ReplayManifestError(
            "Replay-run manifest does not match: " + ", ".join(mismatches) + "."
        )


def load_replay_run_manifest(path: str | Path) -> ReplayRunManifest:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReplayManifestError(f"Unable to read replay-run manifest {path}: {error}") from error
    return ReplayRunManifest.from_json(document)


def write_replay_run_manifest(path: str | Path, manifest: ReplayRunManifest) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(
        json.dumps(manifest.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
