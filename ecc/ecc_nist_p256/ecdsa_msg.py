#!/usr/bin/python3
import hashlib
import binascii
import ecdsa
from ecdsa.ecdsa import Signature, Private_key, Public_key
from ecdsa.util import sigdecode_string
from ecdsa import NIST256p
from ecdsa.curves import orderlen

key = ecdsa.VerifyingKey.from_pem(open('zsh.pub.pem').read())

#msg = open('8888694109B.vbf', 'rb').read()
#sig = open('8888694109B.vbf.sig', 'rb').read()
#sig = open('zsh.sig', 'rb').read()

msg = open('test.txt', 'rb').read()
#msg = b'efgh';
#sig = open('test.sig', 'rb').read()
sig = open('test.sig.bin', 'rb').read()
print(msg);

# { convert der asn.1 { r, s }  to raw s+r 
if not sig[2*2]:
    s = sig[5:5+32]
else:
    s = sig[4:4+32]
r = sig[-32:]
sig = s + r

print(s)
print(r)
# }

result = key.verify(sig, msg, hashlib.sha256)
print(result)
print("-------")
h = hashlib.sha256(open('test.txt','rb').read()).digest()
#h = hashlib.sha256(msg).digest()
print(h)
r2=key.verify_digest(sig, h, sigdecode=sigdecode_string)
print(r2)
