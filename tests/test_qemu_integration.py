from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from focaccia.arch import x86
from focaccia.deterministic import DeterministicLog, RRTraceMetadata
from focaccia.qemu.integration import (
    REPLAY_RUN_MANIFEST_SCHEMA,
    ReplayManifestError,
    ReplayRunManifest,
    create_replay_run_manifest,
    load_replay_run_manifest,
    rr_directory_hash,
    validate_replay_run_manifest,
    write_replay_run_manifest,
)
from focaccia.trace import TraceEnvironment


class FakeDeterministicLog:
    def __init__(self, directory: Path) -> None:
        self.base_directory = directory
        self.metadata = RRTraceMetadata(
            85,
            "rr-trace-v85",
            "0xcaa0b1486c12c629",
            x86.ArchX86(),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        )


def make_artifacts(tmp_path: Path):
    binary = tmp_path / "file-read"
    input_file = tmp_path / "input.txt"
    oracle = tmp_path / "oracle.trace"
    rr = tmp_path / "rr-trace"
    rr.mkdir()
    binary.write_bytes(b"ELF fixture")
    input_file.write_bytes(b"deterministic input\n")
    oracle.write_bytes(b"symbolic trace")
    (rr / "version").write_bytes(b"85\nheader")
    (rr / "events").write_bytes(b"events")
    log = cast(DeterministicLog, FakeDeterministicLog(rr))
    environment = TraceEnvironment(
        str(binary),
        (str(input_file),),
        (),
        start_address=0x401000,
        stop_address=0x401020,
        replay_provenance=str(rr),
        architecture=x86.ArchX86().key,
    )
    return binary, input_file, oracle, rr, log, environment


def test_replay_run_manifest_binds_binary_input_oracle_and_rr_identity(tmp_path):
    binary, input_file, oracle, rr, log, environment = make_artifacts(tmp_path)

    manifest = create_replay_run_manifest(
        binary_path=binary,
        input_paths={"input": input_file},
        argv=(str(input_file),),
        oracle_path=oracle,
        trace_environment=environment,
        deterministic_log=log,
    )

    assert manifest.to_json()["schema"] == REPLAY_RUN_MANIFEST_SCHEMA
    assert manifest.rr_trace_uuid == "00112233445566778899aabbccddeeff"
    assert manifest.rr_directory_sha256 == rr_directory_hash(rr)
    assert manifest.guest_architecture == x86.ArchX86().key

    path = tmp_path / "manifest.json"
    write_replay_run_manifest(path, manifest)
    assert load_replay_run_manifest(path) == manifest
    assert ReplayRunManifest.from_json(json.loads(path.read_text())) == manifest


def test_replay_run_manifest_rejects_changed_consumer_artifacts(tmp_path):
    binary, input_file, oracle, _rr, log, environment = make_artifacts(tmp_path)
    manifest = create_replay_run_manifest(
        binary_path=binary,
        input_paths={"input": input_file},
        argv=(str(input_file),),
        oracle_path=oracle,
        trace_environment=environment,
        deterministic_log=log,
    )
    input_file.write_bytes(b"changed")

    with pytest.raises(ReplayManifestError, match="input file identities"):
        validate_replay_run_manifest(
            manifest,
            binary_path=binary,
            input_paths={"input": input_file},
            argv=(str(input_file),),
            oracle_path=oracle,
            trace_environment=environment,
            deterministic_log=log,
        )


def test_replay_run_manifest_rejects_oracle_from_another_rr_directory(tmp_path):
    binary, input_file, oracle, _rr, log, environment = make_artifacts(tmp_path)
    manifest = create_replay_run_manifest(
        binary_path=binary,
        input_paths={"input": input_file},
        argv=(str(input_file),),
        oracle_path=oracle,
        trace_environment=environment,
        deterministic_log=log,
    )
    wrong_environment = TraceEnvironment(
        str(binary),
        (str(input_file),),
        (),
        start_address=environment.start_address,
        stop_address=environment.stop_address,
        replay_provenance=str(tmp_path / "another-rr-trace"),
        architecture=environment.architecture,
    )

    with pytest.raises(ReplayManifestError, match="oracle RR provenance"):
        validate_replay_run_manifest(
            manifest,
            binary_path=binary,
            input_paths={"input": input_file},
            argv=(str(input_file),),
            oracle_path=oracle,
            trace_environment=wrong_environment,
            deterministic_log=log,
        )


def test_replay_run_manifest_parser_rejects_unknown_schema(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema": "future"}))

    with pytest.raises(ReplayManifestError, match="Unsupported.*future"):
        load_replay_run_manifest(path)


def test_rr_directory_hash_includes_relative_names_and_symlink_targets(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "a").write_bytes(b"same")
    (second / "b").write_bytes(b"same")

    assert rr_directory_hash(first) != rr_directory_hash(second)

    (first / "b").write_bytes(b"different")
    (first / "link").symlink_to("a")
    before = rr_directory_hash(first)
    (first / "link").unlink()
    (first / "link").symlink_to("b")
    assert rr_directory_hash(first) != before

    (first / "link").unlink()
    (first / "link").symlink_to(tmp_path / "outside")
    with pytest.raises(ReplayManifestError, match="symlink escapes"):
        rr_directory_hash(first)
