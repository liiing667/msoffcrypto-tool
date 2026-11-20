"""Agile encryption driven by the declared hash/salt/keyBits parameter families."""

import base64
import io
import unittest
from os.path import dirname, join
from struct import pack

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.format.ooxml import _parseinfo_agile
from msoffcrypto.method.ecma376_agile import ECMA376Agile

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")

#: directory with expected output
OUTPUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"

#: pairs of input/output files: agile SHA1/AES-128, SHA256/AES-256 and SHA512/AES-256
EXAMPLE_FILES = (
    ("ecma376agile_sha1_password.xlsx", "example.xlsx"),
    ("ecma376agile_sha256_password.xlsx", "example.xlsx"),
    ("example_password.xlsx", "example.xlsx"),
)


def _b64(b):
    return base64.b64encode(b).decode("ascii")


#: a valid SHA512/AES-256 agile descriptor used as the template for mutations
_SALT = _b64(b"\x01" * 16)
_HMAC = _b64(b"\x05" * 64)
_VERIFIER_INPUT = _b64(b"\x03" * 16)
_VERIFIER_VALUE = _b64(b"\x04" * 64)
_KEY_VALUE = _b64(b"\x02" * 32)

DESCRIPTOR_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
  <keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="{salt}"/>
  <dataIntegrity encryptedHmacKey="{hmac}" encryptedHmacValue="{hmac}"/>
  <keyEncryptors>
    <keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
      <p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" keyBits="{key_bits}" hashSize="{hash_size}" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="{hash_name}" saltValue="{salt}" encryptedVerifierHashInput="{verifier_input}" encryptedVerifierHashValue="{verifier_value}" encryptedKeyValue="{key_value}"/>
    </keyEncryptor>
  </keyEncryptors>
</encryption>
""".format(
    salt=_SALT,
    hmac=_HMAC,
    verifier_input=_VERIFIER_INPUT,
    verifier_value=_VERIFIER_VALUE,
    key_value=_KEY_VALUE,
    key_bits="256",
    hash_size="64",
    hash_name="SHA512",
)


def parse_descriptor(xml):
    stream = io.BytesIO(pack("<HHI", 4, 4, 0x40) + xml.encode("utf-8"))
    return _parseinfo_agile(stream)


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


class AgileDescriptorValidationTest(unittest.TestCase):
    """The declared parameter families must be validated at parse time."""

    def test_valid_descriptor(self):
        info = parse_descriptor(DESCRIPTOR_TEMPLATE)
        self.assertEqual(info["passwordHashAlgorithm"], "SHA512")
        self.assertEqual(info["passwordKeyBits"], 256)
        self.assertEqual(info["keyDataHashAlgorithm"], "SHA512")
        self.assertEqual(info["keyDataBlockSize"], 16)

    def test_sha256_family_descriptor(self):
        xml = DESCRIPTOR_TEMPLATE.replace('hashAlgorithm="SHA512"', 'hashAlgorithm="SHA256"').replace(
            'hashSize="64"', 'hashSize="32"'
        )
        info = parse_descriptor(xml)
        self.assertEqual(info["passwordHashAlgorithm"], "SHA256")
        self.assertEqual(info["keyDataHashAlgorithm"], "SHA256")

    def test_invalid_key_bits_rejected(self):
        xml = DESCRIPTOR_TEMPLATE.replace('keyBits="256"', 'keyBits="255"')
        with self.assertRaises(exceptions.DecryptionError):
            parse_descriptor(xml)

    def test_unknown_hash_algorithm_rejected(self):
        xml = DESCRIPTOR_TEMPLATE.replace('hashAlgorithm="SHA512"', 'hashAlgorithm="SHA999"')
        with self.assertRaises(exceptions.DecryptionError):
            parse_descriptor(xml)

    def test_inconsistent_hash_size_rejected(self):
        xml = DESCRIPTOR_TEMPLATE.replace('hashAlgorithm="SHA512"', 'hashAlgorithm="SHA256"')
        with self.assertRaises(exceptions.DecryptionError):
            parse_descriptor(xml)

    def test_salt_size_mismatch_rejected(self):
        xml = DESCRIPTOR_TEMPLATE.replace('saltSize="16"', 'saltSize="15"')
        with self.assertRaises(exceptions.DecryptionError):
            parse_descriptor(xml)

    def test_key_value_size_mismatch_rejected(self):
        xml = DESCRIPTOR_TEMPLATE.replace('keyBits="256"', 'keyBits="128"')
        with self.assertRaises(exceptions.DecryptionError):
            parse_descriptor(xml)

    def test_missing_password_encryptor_rejected(self):
        xml = "\n".join(
            line
            for line in DESCRIPTOR_TEMPLATE.splitlines()
            if "p:encryptedKey" not in line
        )
        with self.assertRaises(exceptions.DecryptionError):
            parse_descriptor(xml)


if __name__ == "__main__":
    unittest.main()
