#!/usr/bin/python
# see also: http://cacr.uwaterloo.ca/techreports/1999/corr99-34.pdf

from tinyec import registry
import hashlib, secrets, binascii
from sympy import mod_inverse
import pyasn1
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, namedtype, tag
import hexdump

msg = b'fortest'
print("msg:", msg)

curve = registry.get_curve('secp256r1')
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

#sign
sha = hashlib.sha256()
sha.update(msg)
msg_dgst = sha.digest()
print('msg dgst: ', binascii.hexlify(msg_dgst))

random_k = secrets.randbelow(curve.field.n)
p1 = random_k * curve.g
r = p1.x % curve.field.n
inverse_random_k = mod_inverse(random_k, curve.field.n)
s = inverse_random_k * (int.from_bytes(msg_dgst, "big") + privKey*r) % curve.field.n
print("r: " + hex(r) + ", s: " + hex(s))

#asn1 der
class ECDSASIGNATURE(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('r', univ.Integer()),
            namedtype.NamedType('s', univ.Integer())
            )

res = ECDSASIGNATURE()
res['r'] = r
res['s'] = s
der = encoder.encode(res)
print('signature: ', hexdump.dump(der, sep=''))

#parse signature
rr, rr_s = decoder.decode(der, asn1Spec= ECDSASIGNATURE())
print('r:', hex(rr['r']), 's:', hex(rr['s']))

#verify
sha = hashlib.sha256()
sha.update(msg)
v_dgst = sha.digest()
#print(binascii.hexlify(v_dgst))

w = mod_inverse(rr['s'], curve.field.n)
u1 = int.from_bytes(v_dgst, "big")*w % curve.field.n
u2 = rr['r']*w % curve.field.n
X = int(u1)*curve.g + int(u2)*pubKey
v = X.x %  curve.field.n
print("v: " + hex(v))
verify_result = v == rr['r'] 
print(verify_result)

