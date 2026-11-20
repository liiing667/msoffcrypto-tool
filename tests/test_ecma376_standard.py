"""Standard encryption dispatched by the declared algorithm (AES-128/192/256, RC4)."""

import io
import unittest
from os.path import dirname, join

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.method.ecma376_standard import ECMA376Standard

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")

#: directory with expected output
OUTPUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"

#: pairs of input/output files: standard AES-128, RC4 and AES-256
EXAMPLE_FILES = (
    ("ecma376standard_password.docx", "ecma376standard_password_plain.docx"),
    ("ecma376standard_rc4_password.docx", "ecma376standard_password_plain.docx"),
    ("ecma376standard_aes256_password.docx", "ecma376standard_password_plain.docx"),
)


class ECMA376StandardTest(unittest.TestCase):
    """See module doc."""

    def test_verify_password_and_decrypt(self):
        for in_name, out_name in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD, verify_password=True)
                outfile = io.BytesIO()
                ofile.decrypt(outfile)

            with open(join(OUTPUT_DIR, out_name), "rb") as f:
                self.assertEqual(outfile.getvalue(), f.read())

    def test_wrong_password(self):
        for in_name, _ in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                with self.assertRaises(exceptions.InvalidKeyError):
                    ofile.load_key(password="Password1234", verify_password=True)

    def test_unknown_algId(self):
        with open(join(DATA_DIR, "ecma376standard_unknown_alg_password.docx"), "rb") as f:
            ofile = OfficeFile(f)
            with self.assertRaises(exceptions.DecryptionError):
                ofile.load_key(password=PASSWORD, verify_password=True)

    def test_invalid_keySize(self):
        with open(join(DATA_DIR, "ecma376standard_bad_keysize_password.docx"), "rb") as f:
            ofile = OfficeFile(f)
            with self.assertRaises(exceptions.DecryptionError):
                ofile.load_key(password=PASSWORD, verify_password=True)

    def test_resolve_algorithm(self):
        self.assertEqual(ECMA376Standard.resolve_algorithm(0x660E, 128), "AES")
        self.assertEqual(ECMA376Standard.resolve_algorithm(0x660F, 192), "AES")
        self.assertEqual(ECMA376Standard.resolve_algorithm(0x6610, 256), "AES")
        self.assertEqual(ECMA376Standard.resolve_algorithm(0x6801, 128), "RC4")
        self.assertEqual(ECMA376Standard.resolve_algorithm(0x6801, 40), "RC4")
        for algId, keySize in [
            (0x1234, 128),  # unknown algId
            (0x660E, 192),  # keySize inconsistent with AES-128
            (0x6610, 128),  # keySize inconsistent with AES-256
            (0x6801, 256),  # RC4 keySize too large
            (0x6801, 32),   # RC4 keySize too small
            (0x6801, 41),   # RC4 keySize not a multiple of 8
        ]:
            with self.subTest(algId=algId, keySize=keySize):
                with self.assertRaises(exceptions.DecryptionError):
                    ECMA376Standard.resolve_algorithm(algId, keySize)


if __name__ == "__main__":
    unittest.main()
