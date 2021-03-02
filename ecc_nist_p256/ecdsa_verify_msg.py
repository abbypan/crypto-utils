#!/usr/bin/python3
import hashlib
import binascii
import ecdsa
from ecdsa.ecdsa import Signature, Private_key, Public_key
from ecdsa.util import sigdecode_string
from ecdsa import NIST256p
from ecdsa.curves import orderlen

pub_f = 'ecc_nist_p256_pub.pem'
sig_f = 'test.msg.sig'

msg = b'abcdefg'
print("msg:")
print(msg);

key = ecdsa.VerifyingKey.from_pem(open(pub_f).read())

sig = open(sig_f, 'rb').read()
# { convert der asn.1 { r, s }  to raw s+r 
# https://github.com/warner/python-ecdsa/issues/67
if not sig[2*2]:
    s = sig[5:5+32]
else:
    s = sig[4:4+32]
r = sig[-32:]
sig = s + r

print("r:")
print(r)
print("s:")
print(s)
print("-------\n")
# }

print("Signature verify:")
result = key.verify(sig, msg, hashlib.sha256)
print(result)
print("-------")

print("Hash verify:")
h = hashlib.sha256(msg).digest()
result2=key.verify_digest(sig, h, sigdecode=sigdecode_string)
print(result2)
