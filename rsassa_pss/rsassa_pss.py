#!/usr/bin/python3
# see also: https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Signature/PKCS1_PSS.py

import hashlib, secrets, binascii
import sys

from sympy import mod_inverse
from hexdump import hexdump

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.strxor import strxor
from Crypto.Util.py3compat import bchr
from Crypto.PublicKey import RSA


def octet_len(i):

    iLen = int((len(hex(i)) - 2)/2)
    return iLen

def MGF1(mgfSeed, maskLen, hash_name):

    T = b''

    for counter in range(int((maskLen-1)/hashlib.new(hash_name).digest_size)+1):

        c = long_to_bytes(counter, 4)
        ht = hashlib.new(hash_name)
        ht.update(mgfSeed + c)

        T = T + ht.digest()

    assert(len(T)>=maskLen)

    return T[:maskLen]

def verify_rsa_pss(sLen, mhash, signature, n, e):

    em = pow(signature, e, n)
    emLen = octet_len(em)
    em_hex = hex(em)
    em_hex = em_hex[2:]

    print("em:\n" , em_hex, "\n")

    hLen = octet_len(mhash)

    print("mHash:\n" , hex(mhash), "\n")

    if(emLen < hLen + sLen + 2):
        return 0

    em_tail = em_hex[-2:]

    print("em_tail:\n", em_tail, "\n")

    if(em_tail != "bc"):
        return 0

    maskedDBLen = emLen - hLen - 1
    maskedDB = em_hex[0: maskedDBLen*2]
    
    print("maskedDB:\n", maskedDB, "\n")

    H = em_hex[ maskedDBLen*2 : emLen*2-2 ]

    print("H:\n", H, "\n")

    dbMask = MGF1(bytearray.fromhex(H), maskedDBLen, 'sha256')

    print("dbMask:\n", binascii.hexlify(dbMask), "\n")

    DB = strxor(bytes.fromhex(maskedDB), dbMask)

    print("DB:\n", binascii.hexlify(DB), "\n")

    padding2 = DB[0 : maskedDBLen - sLen]

    print("padding2:\n" , binascii.hexlify(padding2), "\n")

    if(int.from_bytes(padding2, "big") != 0x01):
        return 0

    salt = DB[maskedDBLen - sLen :]

    print("salt:\n", binascii.hexlify(salt), "\n")

    padding1 =bchr(0x00)*8;

    print("padding1:\n" , binascii.hexlify(padding1), "\n")

    m_ = padding1 + bytes.fromhex((hex(mhash))[2:]) + salt

    print("m':\n", binascii.hexlify(m_), "\n")

    hnew = hashlib.sha256()
    hnew.update(m_)
    H_ = hnew.digest()

    print("H':\n", binascii.hexlify(H_), "\n")

    if(bytes.fromhex(H) == H_):
        return 1

    return 0

#rsa public key info

with open(sys.argv[1], 'rb') as f:

    rsa_pub = RSA.import_key(f.read())

n = rsa_pub.n
e = rsa_pub.e

print ("n:\n", n, "\n")
print ("e:\n", e, "\n")

sLen = int(sys.argv[2])
print ("sLen:\n", sLen, "\n")

# signature 

with open(sys.argv[3], 'rb') as file: 

    signature = file.read() 

print("signature:\n", signature, "\n")

# msg 

with open(sys.argv[4], 'rb') as file: 

    mhash = file.read() 

# mhash

if(int(sys.argv[5])!=1):

    hnew = hashlib.sha256()
    hnew.update(mhash)
    mhash = hnew.digest()
    
print("mhash:\n", mhash, "\n")

res = verify_rsa_pss(sLen, int.from_bytes(mhash , byteorder='big'), int.from_bytes(signature, byteorder='big'), n, e)
print("verify result:\n", res, "\n")
