import binascii
import codecs
import os

import pytest

import ed25519


def ed25519_known_answers():
    # Known answers taken from: http://ed25519.cr.yp.to/python/sign.input
    path = os.path.join(os.path.dirname(__file__), "test_data", "ed25519")
    with codecs.open(path, "r", encoding="utf-8") as fp:
        for line in fp:
            x = line.split(":")
            yield (
                # Secret Key
                x[0][0:64].encode("ascii"),
                # Public Key
                x[1].encode("ascii"),
                # Message
                x[2].encode("ascii"),
                # Signed Message
                x[3].encode("ascii"),
                # Signature Only
                binascii.hexlify(
                    binascii.unhexlify(x[3].encode("ascii"))[:64]
                ),
            )


@pytest.mark.parametrize(
    ("secret_key", "public_key", "message", "signed", "signature"),
    ed25519_known_answers(),
)
def test_ed25519_kat(secret_key, public_key, message, signed, signature):
    sk = binascii.unhexlify(secret_key)
    m = binascii.unhexlify(message)

    pk = ed25519.publickey(sk)
    sig = ed25519.signature(m, sk, pk)

    # Assert that the signature and public key are what we expected
    assert binascii.hexlify(pk) == public_key
    assert binascii.hexlify(sig) == signature

    # Validate the signature using the checkvalid routine
    ed25519.checkvalid(sig, m, pk)

    # Assert that we cannot forge a message
    # TODO: Yes this means that we "pass" a test if we can't generate a forged
    #   message. This matches the original test suite.
    with pytest.raises(Exception):
        if len(m) == 0:
            forgedm = b"x"
        else:
            forgedm = b"".join(
                [chr(ord(m[i]) + (i == len(m) - 1)) for i in range(len(m))]
            )
        ed25519.checkvalid(sig, forgedm, pk)


def test_checkparams():
    # Taken from checkparams.py from DJB
    assert ed25519.b >= 10
    assert 8 * len(ed25519.H(b"hash input")) == 2 * ed25519.b
    assert pow(2, ed25519.q - 1, ed25519.q) == 1
    assert ed25519.q % 4 == 1
    assert pow(2, ed25519.l - 1, ed25519.l) == 1
    assert ed25519.l >= 2 ** (ed25519.b - 4)
    assert ed25519.l <= 2 ** (ed25519.b - 3)
    assert pow(ed25519.d, (ed25519.q - 1) // 2, ed25519.q) == ed25519.q - 1
    assert pow(ed25519.I, 2, ed25519.q) == ed25519.q - 1
    assert ed25519.isoncurve(ed25519.B)
    assert ed25519.scalarmult(ed25519.B, ed25519.l) == (0, 1)
