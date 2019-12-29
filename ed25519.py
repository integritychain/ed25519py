# Python 3.7+ Ed25519-SHA-512
# Adapted from https://ed25519.cr.yp.to/software.html retrieved 27 December 2019

import hashlib


# Public API

def get_public_key(secret_key):
    """Calculate and return the secret key corresponding to a public key

    secret_key is BITS//8 bytes; public_key is (encoded) BITS//8 bytes
    """
    h = bytearray(_hash(secret_key)[0:BITS//8])
    h[31] = int((h[31] & 0x7f) | 0x40)
    h[0] = int(h[0] & 0xf8)
    a = int.from_bytes(h, 'little')
    public_key = _scalar_mult(BASE, a)
    return _encode_point(public_key)


def signature(message, secret_key, public_key):
    """Calculate the signature for a message and set of keys

    message is arbitrary length bytes; secret_key and public_key are BITS//8 bytes each
    """
    h = bytearray(_hash(secret_key))
    h[31] = int((h[31] & 0x7f) | 0x40)
    h[0] = int(h[0] & 0xf8)
    a = int.from_bytes(h[0:BITS//8], 'little')
    r = int.from_bytes(_hash(h[BITS//8:] + message), 'little')
    R = _scalar_mult(BASE, r)
    S = (r + int.from_bytes(_hash(_encode_point(R) + public_key + message), 'little') * a) % ORDER
    return _encode_point(R) + _encode_int(S)


def check_valid(signature, message, public_key):
    """Check the validity of a signature given a message and public key

    signature is BITS//4 bytes, message is arbitrary length bytes, public_key is BITS//8 bytes
    Raises exception on failing check
    """
    if len(signature) != BITS//4: raise Exception("signature length is wrong")
    if len(public_key) != BITS//8: raise Exception("public-key length is wrong")
    R = _decode_point(signature[0:BITS//8])
    A = _decode_point(public_key)
    S = _decode_int(signature[BITS//8:BITS//4])
    h = int.from_bytes(_hash(_encode_point(R) + public_key + message), 'little')
    if _scalar_mult(BASE, S) != _edwards_add(R, _scalar_mult(A, h)):
        raise BadSignatureError("signature does not pass verification")


class BadSignatureError(Exception):
    """Signature validation has failed"""
    pass


# Internal functions

def _hash(message):
    """Return 64-byte SHA512 hash of arbitrary-length byte message"""
    return hashlib.sha512(message).digest()


def _inverse(x):
    """Calculate inverse via Fermat's little theorem"""
    return pow(x, PRIME - 2, PRIME)


def _x_recover(y):
    """Recover x from y"""
    xx = (y * y - 1) * _inverse(D * y * y + 1)
    x = pow(xx, (PRIME + 3) // 8, PRIME)
    if (x * x - xx) % PRIME != 0: x = (x * I) % PRIME
    if x % 2 != 0: x = PRIME - x
    return x


def _edwards_add(P, Q):
    """Curve point addition"""
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    x3 = (x1 * y2 + x2 * y1) * _inverse(1 + D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inverse(1 - D * x1 * x2 * y1 * y2)
    return [x3 % PRIME, y3 % PRIME]


def _scalar_mult(P, e):
    """Scalar multiplied by curve point"""
    if e == 0: return [0, 1]
    Q = _scalar_mult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1: Q = _edwards_add(Q, P)
    return Q


def _encode_int(y):
    """Encode integer to 32-bytes"""
    r = y.to_bytes(32, 'little')
    return r


def _encode_point(P):
    """Encode point to 255 bits of Y followed by MSB of X"""
    return ((P[1] & ((1 << 255) - 1)) + ((P[0] & 1) << 255)).to_bytes(32, 'little')


def _get_bit(h, i):
    """Return specified bit from integer for subsequent testing"""
    h1 = int.from_bytes(h, 'little')
    return (h1 >> i) & 0x01


def _is_on_curve(P):
    """Check to confirm point is on curve; return boolean"""
    x = P[0]
    y = P[1]
    return (-x * x + y * y - 1 - D * x * x * y * y) % PRIME == 0


def _decode_int(s):
    """Simple little-endian bytes to integer"""
    return int.from_bytes(s, 'little')


def _decode_point(s):
    """Decode BITS//8 bytes to point"""
    y = int.from_bytes(s, 'little') & ((1 << 255) - 1)
    x = _x_recover(y)
    if x & 1 != _get_bit(s, BITS - 1): x = PRIME - x
    P = [x, y]
    if not _is_on_curve(P): raise Exception("decoding point that is not on curve")
    return P


# Constants (latter five are calculated at runtime)

BITS = 256
PRIME = 2 ** 255 - 19
ORDER = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * _inverse(121666)
I = pow(2, (PRIME - 1) // 4, PRIME)
BASEy = 4 * _inverse(5)
BASEx = _x_recover(BASEy)
BASE = [BASEx % PRIME, BASEy % PRIME]


# From checkparams.py

assert BITS >= 10
assert 8 * len(_hash("hash input".encode("UTF-8"))) == 2 * BITS
assert pow(2, PRIME - 1, PRIME) == 1
assert PRIME % 4 == 1
assert pow(2, ORDER - 1, ORDER) == 1
assert ORDER >= 2 ** (BITS - 4)
assert ORDER <= 2 ** (BITS - 3)
assert pow(D, (PRIME - 1) // 2, PRIME) == PRIME - 1
assert pow(I, 2, PRIME) == PRIME - 1
assert _is_on_curve(BASE)
assert _scalar_mult(BASE, ORDER) == [0, 1]
