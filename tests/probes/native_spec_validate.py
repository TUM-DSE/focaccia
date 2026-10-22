"""Small CLI contract probe for the native specification runner."""

import json
import os
import subprocess
import sys


def main() -> int:
    command = [sys.executable, "-m", "focaccia.native.spec_validate", "--help"]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if (
        result.returncode != 0
        or "--binary" not in result.stdout
        or "--arm-oracle" not in result.stdout
        or "--hardware-profile-helper" not in result.stdout
        or "--expected-stdout-file" not in result.stdout
        or "--output" not in result.stdout
    ):
        print(json.dumps({"status": "failed", "stdout": result.stdout, "stderr": result.stderr}))
        return 1
    fixture = os.environ.get("FOCACCIA_NATIVE_SPEC_FIXTURE")
    if fixture:
        args = [sys.executable, "-m", "focaccia.native.spec_validate", "--binary", fixture]
        architecture = os.environ.get("FOCACCIA_NATIVE_SPEC_ARCH", "aarch64")
        if architecture == "aarch64":
            helper = os.environ.get("FOCACCIA_NATIVE_SPEC_HARDWARE_PROFILE_HELPER")
            oracle = os.environ.get("FOCACCIA_NATIVE_SPEC_TIR_ORACLE")
            if not helper or not oracle:
                print(
                    json.dumps(
                        {
                            "status": "failed",
                            "error": "ARM profile helper and TIR oracle env vars required",
                        }
                    )
                )
                return 1
            args.extend(["--hardware-profile-helper", helper, "--arm-oracle", oracle])
        else:
            for flag, key in (
                ("--intel-oracle", "FOCACCIA_NATIVE_SPEC_INTEL_ORACLE"),
                ("--intel-model", "FOCACCIA_NATIVE_SPEC_INTEL_MODEL"),
                ("--intel-xed", "FOCACCIA_NATIVE_SPEC_INTEL_XED"),
            ):
                value = os.environ.get(key)
                if value:
                    args.extend([flag, value])
        expected = os.environ.get("FOCACCIA_NATIVE_SPEC_EXPECTED_STDOUT_FILE")
        if expected:
            args.extend(["--expected-stdout-file", expected])
        elif "FOCACCIA_NATIVE_SPEC_EXPECTED_STDOUT" in os.environ:
            args.extend(["--expected-stdout", os.environ["FOCACCIA_NATIVE_SPEC_EXPECTED_STDOUT"]])
        else:
            print(json.dumps({"status": "failed", "error": "Expected stdout env var required"}))
            return 1
        wall_timeout = os.environ.get("FOCACCIA_NATIVE_SPEC_WALL_TIMEOUT", "240s")
        command = ["timeout", wall_timeout, *args]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            report = {"stdout": result.stdout, "stderr": result.stderr}
        if result.returncode != 0 or report.get("status") != "accepted":
            print(
                json.dumps(
                    {"status": "failed", "native_report": report, "returncode": result.returncode}
                )
            )
            return 1
        print(
            json.dumps(
                {"status": "passed", "cli": "native-spec-validate", "report": report},
                sort_keys=True,
            )
        )
        return 0
    print(json.dumps({"status": "passed", "cli": "native-spec-validate", "mode": "help-smoke"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
