"""Agile encryption with a hash shorter than the AES block-padded values (SHA1)."""

import io
import os
import shutil
import unittest
from tempfile import NamedTemporaryFile
from os.path import dirname, join

import olefile
import zipfile

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.method.ecma376_agile import ECMA376Agile

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")

#: directory with expected output
OUTPUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"

#: pairs of input/output files: agile SHA1/AES-128 and agile SHA512/AES-256
EXAMPLE_FILES = (
    ("ecma376agile_sha1_password.xlsx", "example.xlsx"),
    ("example_password.xlsx", "example.xlsx"),
)


def _tampered_copy(src_path, stream_name="EncryptedPackage", stream_offset=100):
    """Return the path of an OLE copy with one byte of a stream flipped.

    The tampered byte is located through the OLE FAT chain so that the
    on-disk container stays valid (olefile only supports writing since 0.47).
    """
    with NamedTemporaryFile(delete=False) as tmp:
        shutil.copyfile(src_path, tmp.name)
        path = tmp.name

    ole = olefile.OleFileIO(path)
    try:
        entry = ole.direntries[ole._find(stream_name)]
        if entry.size < ole.minisectorcutoff:
            raise RuntimeError("only regular (FAT) streams are supported")

        sector_index, offset_in_sector = divmod(stream_offset, ole.sectorsize)
        sid = entry.isectStart
        for _ in range(sector_index):
            sid = ole.fat[sid]
        physical_offset = (sid + 1) * ole.sectorsize + offset_in_sector
    finally:
        ole.close()

    with open(path, "r+b") as f:
        f.seek(physical_offset)
        f.write(bytes([f.read(1)[0] ^ 0x01]))

    return path


class ECMA376AgileTest(unittest.TestCase):
    """See module doc."""

    def test_verify_password_and_integrity(self):
        for in_name, out_name in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD, verify_password=True)
                outfile = io.BytesIO()
                ofile.decrypt(outfile, verify_integrity=True)

            with open(join(OUTPUT_DIR, out_name), "rb") as f:
                self.assertEqual(outfile.getvalue(), f.read())

    def test_wrong_password(self):
        for in_name, _ in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                with self.assertRaises(exceptions.InvalidKeyError):
                    ofile.load_key(password="Password1234", verify_password=True)

    def test_tampered_package(self):
        for in_name, _ in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD)
                with ofile.file.openstream("EncryptedPackage") as stream:
                    package = bytearray(stream.read())

            info = ofile.info
            args = (
                ofile.secret_key,
                info["keyDataSalt"],
                info["keyDataHashAlgorithm"],
                info["keyDataBlockSize"],
                info["encryptedHmacKey"],
                info["encryptedHmacValue"],
            )
            self.assertTrue(ECMA376Agile.verify_integrity(*args, io.BytesIO(bytes(package))))

            package[100] ^= 0x01
            self.assertFalse(ECMA376Agile.verify_integrity(*args, io.BytesIO(bytes(package))))

    def test_decrypt_skips_integrity_when_requested(self):
        for in_name, out_name in EXAMPLE_FILES:
            tampered_path = _tampered_copy(join(DATA_DIR, in_name))
            try:
                with self.subTest(in_name), open(tampered_path, "rb") as f:
                    ofile = OfficeFile(f)
                    ofile.load_key(password=PASSWORD)
                    outfile = io.BytesIO()
                    ofile.decrypt(outfile, verify_integrity=False)

                # The tampered byte must not hit the zip tail: the output remains
                # a parseable zip archive (though its content differs).
                self.assertTrue(zipfile.is_zipfile(io.BytesIO(outfile.getvalue())))
            finally:
                os.remove(tampered_path)

    def test_decrypt_verifies_integrity_by_default(self):
        for in_name, out_name in EXAMPLE_FILES:
            tampered_path = _tampered_copy(join(DATA_DIR, in_name))
            try:
                with self.subTest(in_name), open(tampered_path, "rb") as f:
                    ofile = OfficeFile(f)
                    ofile.load_key(password=PASSWORD)
                    with self.assertRaises(exceptions.IntegrityError):
                        ofile.decrypt(io.BytesIO())
            finally:
                os.remove(tampered_path)

    def test_unmodified_file_still_decrypts_by_default(self):
        for in_name, out_name in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD)
                outfile = io.BytesIO()
                ofile.decrypt(outfile)

            with open(join(OUTPUT_DIR, out_name), "rb") as f:
                self.assertEqual(outfile.getvalue(), f.read())


if __name__ == "__main__":
    unittest.main()
