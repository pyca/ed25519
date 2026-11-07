# ed25519.py - Optimized version of the reference implementation of Ed25519
#
# Written in 2011? by Daniel J. Bernstein <djb@cr.yp.to>
#            2013 by Donald Stufft <donald@stufft.io>
#            2013 by Alex Gaynor <alex.gaynor@gmail.com>
#            2013 by Greg Price <price@mit.edu>
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related and neighboring rights to this software to the public domain
# worldwide. This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software. If not, see
# <http://creativecommons.org/publicdomain/zero/1.0/>.

"""
NB: This code is not safe for use with secret keys or secret data.
The only safe use of this code is for verifying signatures on public messages.

Functions for computing the public key of a secret key and for signing
a message are included, namely publickey_unsafe and signature_unsafe,
for testing purposes only.

The root of the problem is that Python's long-integer arithmetic is
not designed for use in cryptography.  Specifically, it may take more
or less time to execute an operation depending on the values of the
inputs, and its memory access patterns may also depend on the inputs.
This opens it to timing and cache side-channel attacks which can
disclose data to an attacker.  We rely on Python's long-integer
arithmetic, so we cannot handle secrets without risking their disclosure.
"""

import hashlib
import math

__version__ = "1.0.dev0"


b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493


def H(m):
    return hashlib.sha512(m).digest()


def pow2(x, p):
    """== pow(x, 2**p, q)"""
    while p > 0:
        x = x * x % q
        p -= 1
    return x


def inv(z):
    r"""$= z^{-1} \mod q$, for z != 0"""
    z %= q
    if z == 0:
        return 0
    return pow(z, -1, q)


d = -121665 * inv(121666) % q
I = pow(2, (q - 1) // 4, q)
d2 = 2 * d % q
_M255 = (1 << 255) - 1


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)

    if (x * x - xx) % q != 0:
        x = (x * I) % q

    if x % 2 != 0:
        x = q - x

    return x


def _sqr_n(x, n):
    """x ** (2 ** n), partially reduced modulo q."""
    M = _M255
    for _ in range(n):
        x = x * x
        x = (x & M) + 19 * (x >> 255)
        x = (x & M) + 19 * (x >> 255)
    return x


def _mul(x, y):
    x = x * y
    x = (x & _M255) + 19 * (x >> 255)
    return (x & _M255) + 19 * (x >> 255)


def _pow22523(z):
    """z ** ((q - 5) // 8) == z ** (2**252 - 3), partially reduced."""
    # Same addition chain as ref10's fe_pow22523.
    z2 = _mul(z, z)
    z9 = _mul(_sqr_n(z2, 2), z)
    z11 = _mul(z9, z2)
    z2_5_0 = _mul(_mul(z11, z11), z9)
    z2_10_0 = _mul(_sqr_n(z2_5_0, 5), z2_5_0)
    z2_20_0 = _mul(_sqr_n(z2_10_0, 10), z2_10_0)
    z2_40_0 = _mul(_sqr_n(z2_20_0, 20), z2_20_0)
    z2_50_0 = _mul(_sqr_n(z2_40_0, 10), z2_10_0)
    z2_100_0 = _mul(_sqr_n(z2_50_0, 50), z2_50_0)
    z2_200_0 = _mul(_sqr_n(z2_100_0, 100), z2_100_0)
    z2_250_0 = _mul(_sqr_n(z2_200_0, 50), z2_50_0)
    return _mul(_sqr_n(z2_250_0, 2), z)


By = 4 * inv(5)
Bx = xrecover(By)
B = (Bx % q, By % q, 1, (Bx * By) % q)
ident = (0, 1, 1, 0)


def edwards_add(P, Q):
    # This is formula sequence 'addition-add-2008-hwcd-3' from
    # http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q

    a = (y1 - x1) * (y2 - x2) % q
    b = (y1 + x1) * (y2 + x2) % q
    c = t1 * d2 * t2 % q
    dd = z1 * 2 * z2 % q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g

    return (x3 % q, y3 % q, z3 % q, t3 % q)


def edwards_double(P):
    # This is formula sequence 'dbl-2008-hwcd' from
    # http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    (x1, y1, z1, _) = P

    a = x1 * x1 % q
    b = y1 * y1 % q
    c = 2 * z1 * z1 % q
    # dd = -a
    e = 2 * x1 * y1 % q
    g = -a + b  # dd + b
    f = g - c
    h = -a - b  # dd - b
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g

    return (x3 % q, y3 % q, z3 % q, t3 % q)


def scalarmult(P, e):
    Q = ident
    for i in range(e.bit_length() - 1, -1, -1):
        Q = edwards_double(Q)
        if (e >> i) & 1:
            Q = edwards_add(Q, P)
    return Q


# Precomputed tables
#
# Points in these tables are stored in one of two "cached" forms that make
# addition cheaper:
#
#   affine Niels:  (y + x, y - x, 2*d*x*y)            for points with z == 1
#   projective:    (Y + X, Y - X, 2*Z, 2*d*T)
#
# Negating a cached point swaps the first two entries and negates the last.


def _to_affine_niels(points):
    """Convert extended points to affine Niels form with one inversion."""
    # Montgomery's simultaneous inversion trick.
    acc = []
    a = 1
    for P in points:
        acc.append(a)
        a = a * P[2] % q
    a = pow(a, -1, q)
    out = [None] * len(points)
    for i in range(len(points) - 1, -1, -1):
        x, y, z, _ = points[i]
        zi = a * acc[i] % q
        a = a * z % q
        x = x * zi % q
        y = y * zi % q
        out[i] = ((y + x) % q, (y - x) % q, d2 * x * y % q)
    return out


def _signed_table(cached):
    """
    Given cached forms of [1, 3, 5, ..., 2n-1] * P, return a list ``t`` of
    length 4n such that t[k] is the cached form of k * P for odd k with
    |k| < 2n (negative k use Python's negative indexing).
    """
    n = len(cached)
    t = [None] * (4 * n)
    for i, c in enumerate(cached):
        t[2 * i + 1] = c
        if len(c) == 3:
            t[-(2 * i + 1)] = (c[1], c[0], -c[2])
        else:
            t[-(2 * i + 1)] = (c[1], c[0], c[2], -c[3])
    return t


def _odd_multiples(P, n):
    """[P, 3P, 5P, ..., (2n-1)P] in extended coordinates."""
    P2 = edwards_double(P)
    out = [P]
    for _ in range(n - 1):
        out.append(edwards_add(out[-1], P2))
    return out


# Fixed-base comb for scalarmult_B: _COMB[i][j] is (j+1) * 2**(_COMB_W*i) * B
# in affine Niels form. Built lazily on first use.
_COMB_W = 5
_COMB = None


def _build_comb():
    global _COMB
    half = 1 << (_COMB_W - 1)
    nwin = (253 + _COMB_W) // _COMB_W + 1
    pts = []
    P = B
    for _ in range(nwin):
        Q = P
        for _ in range(half):
            pts.append(Q)
            Q = edwards_add(Q, P)
        for _ in range(_COMB_W):
            P = edwards_double(P)
    flat = _to_affine_niels(pts)
    _COMB = [flat[i * half : (i + 1) * half] for i in range(nwin)]


def scalarmult_B(e):
    """
    Implements scalarmult(B, e) more efficiently.
    """
    if _COMB is None:
        _build_comb()
    # scalarmult(B, l) is the identity
    e = e % l
    W = _COMB_W
    mask = (1 << W) - 1
    half = 1 << (W - 1)
    full = 1 << W
    M = _M255
    # Completed-coordinates representation of the identity.
    E, F, G, Hh = 0, 1, 1, 1
    for table in _COMB:
        if not e:
            break
        k = e & mask
        if k > half:
            k -= full
        e = (e - k) >> W
        if k == 0:
            continue
        if k > 0:
            ypx, ymx, t2d = table[k - 1]
        else:
            ymx, ypx, t2d = table[-k - 1]
            t2d = -t2d
        X = E * F
        X = (X & M) + 19 * (X >> 255)
        X = (X & M) + 19 * (X >> 255)
        Y = G * Hh
        Y = (Y & M) + 19 * (Y >> 255)
        Y = (Y & M) + 19 * (Y >> 255)
        Z = F * G
        Z = (Z & M) + 19 * (Z >> 255)
        Z = (Z & M) + 19 * (Z >> 255)
        T = E * Hh
        T = (T & M) + 19 * (T >> 255)
        T = (T & M) + 19 * (T >> 255)
        a = (Y - X) * ymx
        a = (a & M) + 19 * (a >> 255)
        bb = (Y + X) * ypx
        bb = (bb & M) + 19 * (bb >> 255)
        c = T * t2d
        c = (c & M) + 19 * (c >> 255)
        dd = Z << 1
        E = bb - a
        F = dd - c
        G = dd + c
        Hh = bb + a
    assert e == 0, e
    return (E * F % q, G * Hh % q, F * G % q, E * Hh % q)


def encodeint(y):
    return (y & ((1 << b) - 1)).to_bytes(b // 8, "little")


def _encode_affine(x, y):
    return ((y % q) | ((x % q & 1) << (b - 1))).to_bytes(b // 8, "little")


def encodepoint(P):
    (x, y, z, _) = P
    zi = inv(z)
    return _encode_affine(x * zi, y * zi)


def bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _clamp(h):
    a = int.from_bytes(h[: b // 8], "little")
    return (a & ((1 << (b - 2)) - 8)) | (1 << (b - 2))


def publickey_unsafe(sk):
    """
    Not safe to use with secret keys or secret data.

    See module docstring.  This function should be used for testing only.
    """
    h = H(sk)
    a = _clamp(h)
    A = scalarmult_B(a)
    return encodepoint(A)


def Hint(m):
    return int.from_bytes(H(m), "little")


def signature_unsafe(m, sk, pk):
    """
    Not safe to use with secret keys or secret data.

    See module docstring.  This function should be used for testing only.
    """
    h = H(sk)
    a = _clamp(h)
    r = Hint(h[b // 8 : b // 4] + m)
    R = encodepoint(scalarmult_B(r))
    S = (r + Hint(R + pk + m) * a) % l
    return R + encodeint(S)


def isoncurve(P):
    (x, y, z, t) = P
    return (
        z % q != 0
        and x * y % q == z * t % q
        and (y * y - x * x - z * z - d * t * t) % q == 0
    )


def decodeint(s):
    if len(s) < b // 8:
        raise IndexError("index out of range")
    return int.from_bytes(s[: b // 8], "little")


def _decode_affine(s):
    if len(s) < b // 8:
        raise IndexError("index out of range")
    y = int.from_bytes(s[: b // 8], "little")
    sign = y >> (b - 1)
    y = (y & ((1 << (b - 1)) - 1)) % q
    # Compute the square root of u/v using a single exponentiation, as in
    # RFC 8032 section 5.1.3.
    yy = y * y
    u = (yy - 1) % q
    v = (d * yy + 1) % q
    v3 = v * v % q * v % q
    x = u * v3 % q * _pow22523(u * v3 * v3 % q * v % q) % q
    vxx = v * x * x % q
    if vxx != u:
        if vxx == q - u:
            x = x * I % q
        else:
            raise ValueError("decoding point that is not on curve")
    if x & 1 != sign:
        x = (q - x) % q
    return x, y


def decodepoint(s):
    x, y = _decode_affine(s)
    return (x, y, 1, x * y % q)


class SignatureMismatch(Exception):
    pass


# Tables for the verification multi-scalar multiplication: odd multiples of
# B and of 2**128 * B, in affine Niels form, for width-_VB_W wNAF.
_VB_W = 8
_VA_W = 4
_VB_TABLES = None
_EIGHT_L = 8 * l
_HALF_BOUND = math.isqrt(_EIGHT_L)


def _build_vb_tables():
    global _VB_TABLES
    n = 1 << (_VB_W - 2)
    B128 = B
    for _ in range(128):
        B128 = edwards_double(B128)
    pts = _odd_multiples(B, n) + _odd_multiples(B128, n)
    flat = _to_affine_niels(pts)
    _VB_TABLES = (_signed_table(flat[:n]), _signed_table(flat[n:]))


def _wnaf(k, w, table, slots):
    """
    Add the cached points for the width-w NAF of k to slots: slots[i] is a
    list of points to add after the doubling for bit position i.
    """
    neg = k < 0
    if neg:
        k = -k
    mask = (1 << w) - 1
    half = 1 << (w - 1)
    full = 1 << w
    pos = 0
    while k:
        z = (k & -k).bit_length() - 1
        k >>= z
        pos += z
        digit = k & mask
        if digit >= half:
            digit -= full
        k -= digit
        pt = table[-digit if neg else digit]
        slot = slots[pos]
        if slot is None:
            slots[pos] = [pt]
        else:
            slot.append(pt)
        k >>= w
        pos += w


def _cached_odd_multiples(x, y, w):
    """
    Width-w signed table (see _signed_table) of projective cached odd
    multiples of the affine point (x, y).  Coordinates are only partially
    reduced modulo q.
    """
    M = _M255
    # P2 = 2 * (x, y) in extended coordinates, 'dbl-2008-hwcd' with Z = 1.
    a = x * x
    a = (a & M) + 19 * (a >> 255)
    bb = y * y
    bb = (bb & M) + 19 * (bb >> 255)
    E = x * y
    E = ((E & M) + 19 * (E >> 255)) << 1
    G = bb - a
    F = G - 2
    Hh = -a - bb
    X = E * F
    X = (X & M) + 19 * (X >> 255)
    X = (X & M) + 19 * (X >> 255)
    Y = G * Hh
    Y = (Y & M) + 19 * (Y >> 255)
    Y = (Y & M) + 19 * (Y >> 255)
    Z = F * G
    Z = (Z & M) + 19 * (Z >> 255)
    Z = (Z & M) + 19 * (Z >> 255)
    T = E * Hh
    T = (T & M) + 19 * (T >> 255)
    T = (T & M) + 19 * (T >> 255)
    T = T * d2
    T = (T & M) + 19 * (T >> 255)
    T = (T & M) + 19 * (T >> 255)
    p2pxs, p2mxs, p2z2, p2t2d = Y + X, Y - X, Z << 1, T

    X, Y, Z = x, y, 1
    T = x * y
    T = (T & M) + 19 * (T >> 255)
    T = (T & M) + 19 * (T >> 255)
    out = []
    for i in range(1 << (w - 2)):
        if i:
            a = (Y - X) * p2mxs
            a = (a & M) + 19 * (a >> 255)
            bb = (Y + X) * p2pxs
            bb = (bb & M) + 19 * (bb >> 255)
            c = T * p2t2d
            c = (c & M) + 19 * (c >> 255)
            dd = Z * p2z2
            dd = (dd & M) + 19 * (dd >> 255)
            E = bb - a
            F = dd - c
            G = dd + c
            Hh = bb + a
            X = E * F
            X = (X & M) + 19 * (X >> 255)
            X = (X & M) + 19 * (X >> 255)
            Y = G * Hh
            Y = (Y & M) + 19 * (Y >> 255)
            Y = (Y & M) + 19 * (Y >> 255)
            Z = F * G
            Z = (Z & M) + 19 * (Z >> 255)
            Z = (Z & M) + 19 * (Z >> 255)
            T = E * Hh
            T = (T & M) + 19 * (T >> 255)
            T = (T & M) + 19 * (T >> 255)
        t2d = T * d2
        t2d = (t2d & M) + 19 * (t2d >> 255)
        t2d = (t2d & M) + 19 * (t2d >> 255)
        out.append((Y + X, Y - X, Z << 1, t2d))
    return _signed_table(out)


def _half_size(h):
    """
    Find (u, v) with u == v * h (mod 8*l), v odd and positive, and both
    |u| and v roughly sqrt(8*l) (about 128 bits), using a truncated
    extended Euclidean algorithm.
    """
    r0, r1 = _EIGHT_L, h % _EIGHT_L
    t0, t1 = 0, 1
    while r1 >= _HALF_BOUND:
        qq, r = divmod(r0, r1)
        r0, r1 = r1, r
        t0, t1 = t1, t0 - qq * t1
    # Consecutive t values are coprime, so at least one of these is odd.
    candidates = [(r0, t0), (r1, t1)]
    if r1:
        qq, r = divmod(r0, r1)
        candidates.append((r, t0 - qq * t1))
    best = None
    for u, v in candidates:
        if v & 1:
            size = max(u.bit_length(), v.bit_length())
            if best is None or size < best[0]:
                best = (size, u, v)
    _, u, v = best
    if v < 0:
        u, v = -u, -v
    return u, v


def checkvalid(s, m, pk):
    """
    Not safe to use when any argument is secret.

    See module docstring.  This function should be used only for
    verifying public signatures of public messages.
    """
    if len(s) != b // 4:
        raise ValueError("signature length is wrong")

    if len(pk) != b // 8:
        raise ValueError("public-key length is wrong")

    Rx, Ry = _decode_affine(s[: b // 8])
    Ax, Ay = _decode_affine(pk)
    S = decodeint(s[b // 8 : b // 4])
    h = Hint(_encode_affine(Rx, Ry) + pk + m)

    # We need to check [S]B == R + [h]A.  Every point on the curve has order
    # dividing 8*l, so for any (u, v) with u == v*h (mod 8*l) and v coprime
    # to 8*l this is equivalent to
    #
    #     [v*S mod l]B - [v]R - [u]A == 0
    #
    # Choosing u and v to be ~128 bits (a reduced basis of the lattice of
    # such pairs) halves the number of doublings needed.  [v*S mod l]B is
    # split as [s0]B + [s1](2**128 B) using precomputed tables.
    if _VB_TABLES is None:
        _build_vb_tables()
    u, v = _half_size(h)
    s = v * S % l
    tb0, tb1 = _VB_TABLES
    # u, v and the halves of s are all about 128 bits, but their wNAFs can
    # be a little longer.
    top = max(s.bit_length() - 128, u.bit_length(), v.bit_length()) + 1
    slots = [None] * (max(top, 129) + 1)
    _wnaf(s & ((1 << 128) - 1), _VB_W, tb0, slots)
    _wnaf(s >> 128, _VB_W, tb1, slots)
    _wnaf(-v, _VA_W, _cached_odd_multiples(Rx, Ry, _VA_W), slots)
    _wnaf(-u, _VA_W, _cached_odd_multiples(Ax, Ay, _VA_W), slots)

    # Straus' algorithm; the accumulator is kept in "completed" coordinates
    # (E, F, G, H), representing the extended point (EF, GH, FG, EH).
    E, F, G, Hh = 0, 1, 1, 1
    M = _M255
    top = len(slots) - 1
    while top >= 0 and slots[top] is None:
        top -= 1
    for i in range(top, -1, -1):
        # Doubling, 'dbl-2008-hwcd'.  Values are only partially reduced
        # modulo q here: "x = (x & M) + 19 * (x >> 255)" maps x to a smaller
        # value congruent modulo q, since 2**255 == 19 (mod q).
        X = E * F
        X = (X & M) + 19 * (X >> 255)
        X = (X & M) + 19 * (X >> 255)
        Y = G * Hh
        Y = (Y & M) + 19 * (Y >> 255)
        Y = (Y & M) + 19 * (Y >> 255)
        Z = F * G
        Z = (Z & M) + 19 * (Z >> 255)
        Z = (Z & M) + 19 * (Z >> 255)
        a = X * X
        a = (a & M) + 19 * (a >> 255)
        bb = Y * Y
        bb = (bb & M) + 19 * (bb >> 255)
        c = Z * Z
        c = ((c & M) + 19 * (c >> 255)) << 1
        E = X * Y
        E = ((E & M) + 19 * (E >> 255)) << 1
        G = bb - a
        F = G - c
        Hh = -a - bb
        adds = slots[i]
        if adds is None:
            continue
        for pt in adds:
            X = E * F
            X = (X & M) + 19 * (X >> 255)
            X = (X & M) + 19 * (X >> 255)
            Y = G * Hh
            Y = (Y & M) + 19 * (Y >> 255)
            Y = (Y & M) + 19 * (Y >> 255)
            Z = F * G
            Z = (Z & M) + 19 * (Z >> 255)
            Z = (Z & M) + 19 * (Z >> 255)
            T = E * Hh
            T = (T & M) + 19 * (T >> 255)
            T = (T & M) + 19 * (T >> 255)
            if len(pt) == 3:
                ypx, ymx, t2d = pt
                dd = Z << 1
            else:
                ypx, ymx, z2, t2d = pt
                dd = Z * z2
                dd = (dd & M) + 19 * (dd >> 255)
            a = (Y - X) * ymx
            a = (a & M) + 19 * (a >> 255)
            bb = (Y + X) * ypx
            bb = (bb & M) + 19 * (bb >> 255)
            c = T * t2d
            c = (c & M) + 19 * (c >> 255)
            E = bb - a
            F = dd - c
            G = dd + c
            Hh = bb + a

    # The result is the identity iff X == 0 and Y == Z.
    if E * F % q != 0 or (G * Hh - F * G) % q != 0:
        raise SignatureMismatch("signature does not pass verification")
