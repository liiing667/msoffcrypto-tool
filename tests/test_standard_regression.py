"""Standard encryption (no HMAC) must keep decrypting with the new defaults."""

import io
import unittest
from os.path import dirname, join

from msoffcrypto import OfficeFile

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")

#: directory with expected output
OUTPUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"


class ECMA376StandardRegressionTest(unittest.TestCase):
    """See module doc."""

    def test_standard_file_decrypts_with_default_arguments(self):
        with open(join(DATA_DIR, "ecma376standard_password.docx"), "rb") as f:
            ofile = OfficeFile(f)
            ofile.load_key(password=PASSWORD)
            outfile = io.BytesIO()
            ofile.decrypt(outfile)

        with open(
            join(OUTPUT_DIR, "ecma376standard_password_plain.docx"), "rb"
        ) as f:
            self.assertEqual(outfile.getvalue(), f.read())

    def test_standard_file_accepts_verify_integrity_kwarg(self):
        # The CLI always passes verify_integrity to OOXML files; standard
        # encryption has no HMAC, so the flag is accepted and ignored.
        with open(join(DATA_DIR, "ecma376standard_password.docx"), "rb") as f:
            ofile = OfficeFile(f)
            ofile.load_key(password=PASSWORD)
            outfile = io.BytesIO()
            ofile.decrypt(outfile, verify_integrity=True)

        with open(
            join(OUTPUT_DIR, "ecma376standard_password_plain.docx"), "rb"
        ) as f:
            self.assertEqual(outfile.getvalue(), f.read())


if __name__ == "__main__":
    unittest.main()
