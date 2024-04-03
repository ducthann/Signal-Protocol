import random

class EllipticCurve:
    def __init__(self, p, a, b, g, n, h):
        self.p = p  # Field characteristic
        self.a = a  # Curve coefficient a
        self.b = b  # Curve coefficient b
        self.g = g  # Base point
        self.n = n  # Subgroup order
        self.h = h  # Subgroup cofactor

# take from https://neuromancer.sk/std/other/Curve25519
curve = EllipticCurve(
    # Field characteristic.
    p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
    # Curve coefficients.
    a = 0x76d06, b = 0x01,
    # Base point.
    g = (0x09, 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9),
    # Subgroup order.
    n = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
    # Subgroup cofactor.
    h = 0x08,)


# Modular arithmetic ##########################################################

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.

    This function returns the only integer x such that (x * k) % p == 1.

    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    x = old_s
    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point
    # y^2 - x^3 - ax - b
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p, -y3 % curve.p)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    return result


# Keypair generation and ECDHE ################################################

def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key

def compress(pubKey):
    x, y = pubKey
    compressed = (y & 1) << 255 | x
    return compressed

def decompress(compressed):
    x_compressed = compressed & ((1 << 255) - 1)  # Extract lower 255 bits
    y_bit = compressed >> 255  # Extract the highest bit
    y = y_bit
    x = x_compressed
    return x, y

def exchange(alice_private_key, bob_public_key):
    return compress(scalar_mult(alice_private_key, bob_public_key)).to_bytes(32, 'big')


# Alice generates her own keypair.
#will write the test

"""
alice_private_key, alice_public_key = make_keypair()
bob_private_key, bob_public_key = make_keypair()

alice_private_key1, alice_public_key1 = make_keypair()
bob_private_key1, bob_public_key1 = make_keypair()

#alice_private_key_byte_data = alice_private_key.to_bytes(32, 'big')
#alice_public_key_byte_data = alice_public_key.to_bytes(32, 'big')
print("Bob's private key:", hex(alice_private_key))
print("Alice's public key:", compress(alice_public_key))
#print("Alice's public key: (0x{:x}, 0x{:x})".format(*alice_public_key))

# Bob generates his own key pair.
bob_private_key, bob_public_key = make_keypair()
print("Bob's private key:", hex(bob_private_key))
print("Bob's public key:", compress(bob_public_key))
#print("Bob's public key: (0x{:x}, 0x{:x})".format(*bob_public_key))

# Alice and Bob exchange their public keys and calculate the shared secret.
s1 = compress(scalar_mult(alice_private_key, bob_public_key)).to_bytes(32, 'big')
s2 = compress(scalar_mult(bob_private_key, alice_public_key)).to_bytes(32, 'big')
print(s1 == s2)

"""



"""
print("Shared secret:", exchange(alice_private_key, bob_public_key))
print("Shared secret:", exchange(bob_private_key, alice_public_key))
print("Shared secret:", exchange(bob_private_key1, alice_public_key1))
"""

#print('Shared secret: (0x{:x}, 0x{:x})'.format(*s1))