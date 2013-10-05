import hashlib
import operator
import sys


__version__ = "1.0.dev0"


# Useful for very coarse version differentiation.
PY3 = sys.version_info[0] == 3

if PY3:
    indexbytes = operator.getitem
    intlist2bytes = bytes
    int2byte = operator.methodcaller("to_bytes", 1, "big")
else:
    int2byte = chr

    def indexbytes(buf, i):
        return ord(buf[i])

    def intlist2bytes(l):
        return b"".join(chr(c) for c in l)


b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def H(m):
    return hashlib.sha512(m).digest()


def pow2(x, p):
    """== pow(x, 2**p, q)"""
    while p > 0:
        x = x * x % q
        p -= 1
    return x

def inv(z):
    """Use the extended Euclidean algorithm to find the inverse mod q.

       Python's arithmetic is abysmal -- multiplication and division
       are both quadratic, so this is likely the fastest way to do this.

       See, for example, H. Cohen, A Course in Computational Algebraic Number
       Theory, Algorithm 1.3.6
    """
    a, b = z, q
    if b == 0:
        return 1
    u = 1
    d = a
    r = 0
    div = b
    while True:
        if div == 0:
          return u
        qq, div, d = d // div, d % div, div
        r, u = u - qq * r, r


d = -121665 * inv(121666)
I = pow(2, (q - 1) // 4, q)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)

    if (x * x - xx) % q != 0:
        x = (x * I) % q

    if x % 2 != 0:
        x = q-x

    return x


By = 4 * inv(5)
Bx = xrecover(By)
B = (Bx % q, By % q)


def edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2)

    return (x3 % q, y3 % q)


def scalarmult(P, e):
    if e == 0:
        return (0, 1)

    Q = scalarmult(P, e // 2)
    Q = edwards(Q, Q)

    if e & 1:
        Q = edwards(Q, P)

    return Q


def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return b''.join([
        int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
        for i in range(b//8)
    ])


def encodepoint(P):
    x = P[0]
    y = P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return b''.join([
        int2byte(sum([bits[i * 8 + j] << j for j in range(8)]))
        for i in range(b//8)
    ])


def bit(h, i):
    return (indexbytes(h, i // 8) >> (i % 8)) & 1


def publickey(sk):
    h = H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in range(3, b - 2))
    A = scalarmult(B, a)
    return encodepoint(A)


def Hint(m):
    h = H(m)
    return sum(2 ** i * bit(h, i) for i in range(2 * b))


def signature(m, sk, pk):
    h = H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in range(3, b - 2))
    r = Hint(
        intlist2bytes([indexbytes(h, j) for j in range(b // 8, b // 4)]) + m
    )
    R = scalarmult(B, r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)


def isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def decodeint(s):
    return sum(2 ** i * bit(s, i) for i in range(0, b))


def decodepoint(s):
    y = sum(2 ** i * bit(s, i) for i in range(0, b - 1))
    x = xrecover(y)

    if x & 1 != bit(s,  b-1):
        x = q-x

    P = (x, y)

    if not isoncurve(P):
        raise Exception("decoding point that is not on curve")

    return P


def checkvalid(s, m, pk):
    if len(s) != b // 4:
        raise Exception("signature length is wrong")

    if len(pk) != b // 8:
        raise Exception("public-key length is wrong")

    R = decodepoint(s[:b // 8])
    A = decodepoint(pk)
    S = decodeint(s[b // 8:b // 4])
    h = Hint(encodepoint(R) + pk + m)

    if scalarmult(B, S) != edwards(R, scalarmult(A, h)):
        raise Exception("signature does not pass verification")
