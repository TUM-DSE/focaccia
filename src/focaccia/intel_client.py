"""Bounded transport to the source-derived Intel/TIR evaluator.

This module defines no instruction behavior and never accepts observed outputs
as oracle inputs. The caller owns immutable pre-boundary evidence and must check
returned state/write predictions against separate output observations.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import time


class IntelOracleError(RuntimeError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntelOracleError(f"duplicate oracle key {key!r}")
        result[key] = value
    return result


class IntelOracle:
    def __init__(self, executable: str, model: Path, *, timeout: float = 60,
                 max_response: int = 16 * 1024 * 1024):
        if timeout <= 0 or max_response <= 0:
            raise ValueError("oracle limits must be positive")
        self.timeout = timeout
        self.max_response = max_response
        self.process = subprocess.Popen(
            [executable, "--json-lines", str(model)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0,
        )
        self.closed = False
        self.requests = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.process.stdin.close()
        try:
            self.process.wait(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        finally:
            self.process.stdout.close()

    def request(self, request: dict) -> dict:
        if self.closed:
            raise IntelOracleError("oracle is closed")
        raw = json.dumps(request, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(raw) > self.max_response:
            raise IntelOracleError("oracle request exceeds byte limit")
        deadline = time.monotonic() + self.timeout
        try:
            offset = 0
            while offset < len(raw):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [self.process.stdin], [], remaining)[1]:
                    raise IntelOracleError("oracle request timed out")
                offset += os.write(self.process.stdin.fileno(), raw[offset:offset+4096])
            data = bytearray()
            while not data.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                    raise IntelOracleError("oracle response timed out")
                chunk = os.read(self.process.stdout.fileno(), min(65536, self.max_response + 1 - len(data)))
                if not chunk:
                    raise IntelOracleError("oracle exited before completing its response")
                data.extend(chunk)
                if len(data) > self.max_response or b"\n" in data[:-1]:
                    raise IntelOracleError("oversized or multiple oracle responses")
            response = json.loads(data, object_pairs_hook=_pairs)
            if not isinstance(response, dict) or type(response.get("ok")) is not bool:
                raise IntelOracleError("malformed oracle response")
            self.requests += 1
            return response
        except (OSError, ValueError, IntelOracleError) as error:
            self.close()
            raise IntelOracleError(str(error)) from error

    def checked(self, request: dict) -> dict:
        response = self.request(request)
        if not response["ok"]:
            raise IntelOracleError(f"TIR rejected {request.get('function', request.get('op'))}: {response}")
        return response


def bits(value: int, width: int) -> dict[str, str]:
    if type(value) is not int or type(width) is not int or not 1 <= width <= 2048 or not 0 <= value < (1 << width):
        raise IntelOracleError("invalid bitvector input")
    return {"bits": format(value, f"0{width}b")}


def bit_value(value: object, width: int) -> int:
    if not isinstance(value, dict) or set(value) != {"bits"}:
        raise IntelOracleError("expected bitvector result")
    raw = value["bits"]
    if not isinstance(raw, str) or len(raw) != width or any(c not in "01" for c in raw):
        raise IntelOracleError("invalid bitvector result width/content")
    return int(raw, 2)
