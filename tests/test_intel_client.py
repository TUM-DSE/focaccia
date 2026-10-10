"""Protocol tests only; fake executables do not provide ISA semantics."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "intel_client", Path(__file__).parents[1] / "src/focaccia/intel_client.py")
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def executable(self, body):
        path = Path(self.temp.name) / "oracle"
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o700)
        return str(path)

    def test_roundtrip_and_error_is_not_success(self):
        exe = self.executable('import sys,json\nfor line in sys.stdin:\n r=json.loads(line)\n print(json.dumps({"ok":r.get("pass",False)}),flush=True)\n')
        with client.IntelOracle(exe, Path("unused"), timeout=1) as oracle:
            self.assertEqual(oracle.checked({"pass": True}), {"ok": True})
            with self.assertRaises(client.IntelOracleError):
                oracle.checked({"pass": False})
            self.assertEqual(oracle.requests, 2)

    def test_duplicate_fields_fail_closed(self):
        exe = self.executable('import sys\nsys.stdin.readline()\nprint(\'{"ok":false,"ok":true}\',flush=True)\n')
        with client.IntelOracle(exe, Path("unused"), timeout=1) as oracle:
            with self.assertRaises(client.IntelOracleError):
                oracle.request({})
            self.assertTrue(oracle.closed)

    def test_incomplete_response_fails_closed(self):
        exe = self.executable('import sys\nsys.stdin.readline()\nsys.stdout.write(\'{"ok":true}\')\n')
        with client.IntelOracle(exe, Path("unused"), timeout=1) as oracle:
            with self.assertRaises(client.IntelOracleError):
                oracle.request({})

    def test_bitvectors_are_exact_width(self):
        self.assertEqual(client.bits(5, 4), {"bits": "0101"})
        self.assertEqual(client.bit_value({"bits": "0101"}, 4), 5)
        for value in ({"bits": "101"}, {"bits": "01xx"}, {"bits": "0101", "extra": 0}):
            with self.assertRaises(client.IntelOracleError):
                client.bit_value(value, 4)
        with self.assertRaises(client.IntelOracleError):
            client.bits(16, 4)


if __name__ == "__main__":
    unittest.main()
