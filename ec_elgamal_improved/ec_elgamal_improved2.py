#!/usr/bin/python
# EC ElGamal (improved version)
# see also: http://zoo.cs.yale.edu/classes/cs467/2017f/lectures/ln13.pdf

from tinyec import registry
from tinyec import ec
import secrets
from sympy import mod_inverse

def encrypt(curve, pub, m):
    k = secrets.randbelow(curve.field.n)
    print("k: " + hex(k))

    r = k*pub
    print("r: " + hex(r.x) + ", " +hex(r.y))

    y1 = k*curve.g
    print("cipher y1: " + hex(y1.x) + ", " +hex(y1.y))

    inv_r_x = mod_inverse(r.x, curve.field.p)
    print("inv of r.x: " + hex(inv_r_x))
    y2 = m*inv_r_x % curve.field.p
    print("cipher y2: " + hex(y2))

    return (y1, y2)

def decrypt(curve, priv, y1, y2):
    r = priv*y1
    print("r: " + hex(r.x) + ", " +hex(r.y))

    m = y2*r.x % curve.field.p
    print("m: " + hex(m))

    return m

#curve_params = {"p": 0x000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
#"a": 0x000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc,
#"b": 0x00000051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
#"g": (0x000000c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
#0x0000011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650),
#"n": 0x000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
#"h": 0x1}
#sub_group = ec.SubGroup(curve_params["p"], curve_params["g"], curve_params["n"], curve_params["h"])
#curve = ec.Curve(curve_params["a"], curve_params["b"], sub_group, "mytest")

#curve = registry.get_curve('brainpoolP256r1')

#secp256r1 = nist p-256
curve = registry.get_curve('secp256r1')

keypair=ec.make_keypair(curve)

#m = secrets.randbelow(curve.field.p)
m = secrets.randbelow(0xffffffffffffffffffffffffffffffff)
print("plain-text:\nm: " + hex(m))

print("\nencrypt:")
(y1, y2) = encrypt(curve, keypair.pub, m)

print("\ndecrypt:")
decrypt_m = decrypt(curve, keypair.priv, y1, y2)
