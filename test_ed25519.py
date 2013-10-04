import binascii
import codecs
import os

import pytest

import ed25519


def ed25519_known_answers():
    # Known answers taken from: http://ed25519.cr.yp.to/python/sign.input
    answers = []

    path = os.path.join(os.path.dirname(__file__), "test_data", "ed25519")
    with codecs.open(path, "r", encoding="utf-8") as fp:
        for line in fp:
            x = line.split(":")
            answers.append({
                "secret_key": x[0][0:64].encode("ascii"),
                "public_key": x[1].encode("ascii"),
                "message": x[2].encode("ascii"),
                "signed": x[3].encode("ascii"),
                "signature": binascii.hexlify(
                    binascii.unhexlify(x[3].encode("ascii"))[:64]
                ),
            })

    return answers


@pytest.mark.parametrize(
    ("secret_key", "public_key", "message", "signed", "signature"),
    [
        (
            x["secret_key"], x["public_key"], x["message"], x["signed"],
            x["signature"],
        )
        for x in ed25519_known_answers()
    ]
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
