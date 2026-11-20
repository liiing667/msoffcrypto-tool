"""CLI behavior around the agile payload integrity check."""

import os
import subprocess
import sys
import tempfile
import unittest
from os.path import dirname, join

from tests.test_ecma376_agile import _tampered_copy

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")

#: directory with expected output
OUTPUT_DIR = join(dirname(__file__), "outputs")

REPO_ROOT = dirname(dirname(__file__))

PASSWORD = "Password1234_"

AGILE_FILES = (
    "ecma376agile_sha1_password.xlsx",
    "example_password.xlsx",
)


class IntegrityCLITest(unittest.TestCase):
    """See module doc."""

    def _run_cli(self, *args):
        env = dict(os.environ)
        env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, "-m", "msoffcrypto.__main__", *args],
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_tampered_file_rejected_by_default(self):
        for in_name in AGILE_FILES:
            with self.subTest(in_name):
                tampered_path = _tampered_copy(join(DATA_DIR, in_name))
                try:
                    with tempfile.NamedTemporaryFile() as out:
                        proc = self._run_cli("-p", PASSWORD, tampered_path, out.name)
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertIn("integrity", proc.stderr.decode().lower())
                finally:
                    os.remove(tampered_path)

    def test_tampered_file_allowed_with_no_integrity(self):
        for in_name in AGILE_FILES:
            with self.subTest(in_name):
                tampered_path = _tampered_copy(join(DATA_DIR, in_name))
                try:
                    with tempfile.NamedTemporaryFile() as out:
                        proc = self._run_cli(
                            "--no-integrity", "-p", PASSWORD, tampered_path, out.name
                        )
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        self.assertGreater(os.path.getsize(out.name), 0)
                finally:
                    os.remove(tampered_path)

    def test_wrong_password_reported_as_key_error(self):
        for in_name in AGILE_FILES:
            with self.subTest(in_name):
                with tempfile.NamedTemporaryFile() as out:
                    proc = self._run_cli("-p", "wrong-password", join(DATA_DIR, in_name), out.name)
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotEqual(proc.returncode, 2)
                self.assertIn("InvalidKeyError", proc.stderr.decode())

    def test_unmodified_agile_file_decrypts(self):
        for in_name in ("example_password.xlsx",):
            with self.subTest(in_name):
                with tempfile.NamedTemporaryFile() as out:
                    proc = self._run_cli("-p", PASSWORD, join(DATA_DIR, in_name), out.name)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    with open(out.name, "rb") as f:
                        output = f.read()
                with open(join(OUTPUT_DIR, "example.xlsx"), "rb") as f:
                    self.assertEqual(output, f.read())


if __name__ == "__main__":
    unittest.main()
