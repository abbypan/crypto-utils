#!/usr/bin/python
import secrets, binascii
import os
import sys
from buffered_encryption.aesgcm import EncryptionIterator, DecryptionIterator

key = binascii.unhexlify(sys.argv[1])
#aad =  binascii.unhexlify(sys.argv[2])
aad=binascii.unhexlify('')

plaintext_fname = sys.argv[2]
ciphertext_fname =  sys.argv[3]

plaintext = open(plaintext_fname,"rb")

#enc = EncryptionIterator(plaintext,key,aad)
enc = EncryptionIterator(plaintext,key,aad)
with open(ciphertext_fname,"wb") as ciphertext:
    for chunk in enc:
        ciphertext.write(chunk)
plaintext.close()

print("iv: " + str(binascii.hexlify(enc.iv)))
print("tag: " + str(binascii.hexlify(enc.tag)))

