import io
import logging
from hashlib import sha1
from struct import pack, unpack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from msoffcrypto import exceptions

try:
    # NOTE: Avoid DeprecationWarning since cryptography>=43.0
    # TODO: .algorithm differs from the official documentation
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import ARC4

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# [MS-OFFCRYPTO] 2.3.5.2 EncryptionHeader AlgID
ALG_ID_AES128 = 0x0000660E
ALG_ID_AES192 = 0x0000660F
ALG_ID_AES256 = 0x00006610
ALG_ID_RC4 = 0x00006801

_AES_KEY_SIZES = {
    ALG_ID_AES128: 128,
    ALG_ID_AES192: 192,
    ALG_ID_AES256: 256,
}

# For RC4 the key size MUST be between 40 and 128 bits, in increments of 8 bits
_RC4_MIN_KEY_SIZE = 40
_RC4_MAX_KEY_SIZE = 128


class ECMA376Standard:
    def __init__(self):
        pass

    @staticmethod
    def algorithm_name(algId):
        r"""
        Return the algorithm family name ("AES" or "RC4") for the given AlgID,
        or None if the AlgID is not supported.
        """
        if algId in _AES_KEY_SIZES:
            return "AES"
        elif algId == ALG_ID_RC4:
            return "RC4"
        return None

    @staticmethod
    def resolve_algorithm(algId, keySize):
        r"""
        Return the algorithm family name ("AES" or "RC4") for the given AlgID,
        raising DecryptionError if the AlgID is unknown or if keySize is
        inconsistent with the algorithm family.
        """
        name = ECMA376Standard.algorithm_name(algId)
        if name is None:
            raise exceptions.DecryptionError(
                "Unsupported algorithm (algId: 0x{:08X})".format(algId)
            )
        if name == "AES":
            if keySize != _AES_KEY_SIZES[algId]:
                raise exceptions.DecryptionError(
                    "keySize {} is inconsistent with algId 0x{:08X} (AES-{})".format(
                        keySize, algId, _AES_KEY_SIZES[algId]
                    )
                )
        elif name == "RC4":
            if (
                keySize % 8 != 0
                or not _RC4_MIN_KEY_SIZE <= keySize <= _RC4_MAX_KEY_SIZE
            ):
                raise exceptions.DecryptionError(
                    "Invalid RC4 keySize {} (must be between {} and {} bits, in increments of 8)".format(
                        keySize, _RC4_MIN_KEY_SIZE, _RC4_MAX_KEY_SIZE
                    )
                )
        return name

    @staticmethod
    def decrypt(key, ibuf, algorithm="AES"):
        r"""
        Return decrypted data.

        """
        obuf = io.BytesIO()
        totalSize = unpack("<I", ibuf.read(4))[0]
        logger.debug("totalSize: {}".format(totalSize))
        ibuf.seek(8)
        if algorithm == "AES":
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        elif algorithm == "RC4":
            cipher = Cipher(ARC4(key), mode=None, backend=default_backend())
        else:
            raise exceptions.DecryptionError(
                "Unsupported algorithm: {}".format(algorithm)
            )
        decryptor = cipher.decryptor()
        x = ibuf.read()
        dec = decryptor.update(x) + decryptor.finalize()
        obuf.write(dec[:totalSize])
        return obuf.getvalue()  # return obuf.getbuffer()

    @staticmethod
    def verifykey(key, encryptedVerifier, encryptedVerifierHash, algorithm="AES"):
        r"""
        Return True if the given intermediate key is valid.

            >>> key = b'@\xb1:q\xf9\x0b\x96n7T\x08\xf2\xd1\x81\xa1\xaa'
            >>> encryptedVerifier = b'Qos.\x96o\xac\x17\xb1\xc5\xd7\xd8\xcc6\xc9('
            >>> encryptedVerifierHash = b'+ah\xda\xbe)\x11\xad+\xd3|\x17Ft\\\x14\xd3\xcf\x1b\xb1@\xa4\x8fNo=#\x88\x08r\xb1j'
            >>> ECMA376Standard.verifykey(key, encryptedVerifier, encryptedVerifierHash)
            True
        """
        # TODO: For consistency with Agile, rename method to verify_password or the like
        logger.debug([key, encryptedVerifier, encryptedVerifierHash])
        # https://msdn.microsoft.com/en-us/library/dd926426(v=office.12).aspx
        if algorithm == "AES":
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            verifier = decryptor.update(encryptedVerifier)
            decryptor = cipher.decryptor()
            verifierHash = decryptor.update(encryptedVerifierHash)
        elif algorithm == "RC4":
            # The verifier and its hash are encrypted as a single RC4 stream
            cipher = Cipher(ARC4(key), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            verifier = decryptor.update(encryptedVerifier)
            verifierHash = decryptor.update(encryptedVerifierHash)
        else:
            raise exceptions.DecryptionError(
                "Unsupported algorithm: {}".format(algorithm)
            )
        expected_hash = sha1(verifier).digest()
        verifierHash = verifierHash[: sha1().digest_size]
        return expected_hash == verifierHash

    @staticmethod
    def makekey_from_password(
        password, algId, algIdHash, providerType, keySize, saltSize, salt
    ):
        r"""
        Generate intermediate key from given password.

            >>> password = 'Password1234_'
            >>> algId = 0x660e
            >>> algIdHash = 0x8004
            >>> providerType = 0x18
            >>> keySize = 128
            >>> saltSize = 16
            >>> salt = b'\xe8\x82fI\x0c[\xd1\xee\xbd+C\x94\xe3\xf80\xef'
            >>> expected = b'@\xb1:q\xf9\x0b\x96n7T\x08\xf2\xd1\x81\xa1\xaa'
            >>> ECMA376Standard.makekey_from_password(password, algId, algIdHash, providerType, keySize, saltSize, salt) == expected
            True
        """
        ECMA376Standard.resolve_algorithm(algId, keySize)
        logger.debug(
            [
                password,
                hex(algId),
                hex(algIdHash),
                hex(providerType),
                keySize,
                saltSize,
                salt,
            ]
        )
        xor_bytes = lambda a, b: bytearray(
            [p ^ q for p, q in zip(bytearray(a), bytearray(b))]
        )  # bytearray() for Python 2 compat.

        # https://msdn.microsoft.com/en-us/library/dd925430(v=office.12).aspx
        ITER_COUNT = 50000

        password = password.encode("UTF-16LE")
        h = sha1(salt + password).digest()
        for i in range(ITER_COUNT):
            ibytes = pack("<I", i)
            h = sha1(ibytes + h).digest()
        block = 0
        blockbytes = pack("<I", block)
        hfinal = sha1(h + blockbytes).digest()
        cbRequiredKeyLength = keySize // 8
        cbHash = sha1().digest_size
        buf1 = b"\x36" * 64
        buf1 = xor_bytes(hfinal, buf1[:cbHash]) + buf1[cbHash:]
        x1 = sha1(buf1).digest()
        buf2 = b"\x5c" * 64
        buf2 = xor_bytes(hfinal, buf2[:cbHash]) + buf2[cbHash:]
        x2 = sha1(buf2).digest()  # In spec but unused
        x3 = x1 + x2
        keyDerived = x3[:cbRequiredKeyLength]
        logger.debug(keyDerived)
        return keyDerived
