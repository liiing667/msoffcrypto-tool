#!/usr/bin/env python

"""Test XOR obfuscation (fObfuscation=1) support for MS-DOC files."""

import io
import sys
import unittest
from os.path import abspath, dirname
from os.path import join as pjoin

# add base dir to path so we always import local msoffcrypto
TEST_BASE_DIR = dirname(abspath(__file__))
MODULE_BASE_DIR = dirname(TEST_BASE_DIR)
if sys.path[0] != MODULE_BASE_DIR:
    sys.path.insert(0, MODULE_BASE_DIR)
import msoffcrypto
from msoffcrypto import exceptions

#: password for the XOR-obfuscated test file
PASSWORD = "123456789012345"

#: XOR-obfuscated input and its plaintext equivalent
INPUT_FILE = pjoin(TEST_BASE_DIR, "inputs", "xor_password_123456789012345.doc")
PLAIN_FILE = pjoin(TEST_BASE_DIR, "inputs", "plain.doc")


class Doc97XorObfuscation(unittest.TestCase):
    """See module doc."""

    def test_wrong_password_rejected(self):
        """load_key must raise InvalidKeyError for a wrong password."""
        with open(INPUT_FILE, "rb") as f:
            officefile = msoffcrypto.OfficeFile(f)
            self.assertTrue(officefile.is_encrypted())
            with self.assertRaises(exceptions.InvalidKeyError):
                officefile.load_key(password="wrongpassword")

    def test_decrypt_matches_plain(self):
        """Decryption with the correct password yields the plain.doc streams."""
        import olefile

        with open(INPUT_FILE, "rb") as f:
            officefile = msoffcrypto.OfficeFile(f)
            officefile.load_key(password=PASSWORD)
            out = io.BytesIO()
            officefile.decrypt(out)

        with open(PLAIN_FILE, "rb") as f:
            plain = f.read()

        ole_plain = olefile.OleFileIO(io.BytesIO(plain))
        ole_out = olefile.OleFileIO(io.BytesIO(out.getvalue()))
        for stream in ("WordDocument", "1Table"):
            self.assertEqual(
                ole_plain.openstream(stream).read(),
                ole_out.openstream(stream).read(),
            )

    def test_output_not_marked_encrypted(self):
        """The decrypted output must clear fEncrypted/fObfuscation."""
        with open(INPUT_FILE, "rb") as f:
            officefile = msoffcrypto.OfficeFile(f)
            officefile.load_key(password=PASSWORD)
            out = io.BytesIO()
            officefile.decrypt(out)

        out.seek(0)
        decrypted = msoffcrypto.OfficeFile(out)
        self.assertFalse(decrypted.is_encrypted())
        self.assertEqual(decrypted.info.fib.base.fEncrypted, 0)
        self.assertEqual(decrypted.info.fib.base.fObfuscation, 0)


if __name__ == "__main__":
    unittest.main()
