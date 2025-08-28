#!/usr/bin/python
import secrets, binascii
import os
import sys
from buffered_encryption.aesctr import EncryptionIterator

key = binascii.unhexlify(sys.argv[1])
iv = os.urandom(16)

plaintext_fname = sys.argv[2]
ciphertext_fname =  sys.argv[3]

plaintext = open(plaintext_fname,"rb")

enc = EncryptionIterator(plaintext,key,iv)
with open(ciphertext_fname,"wb") as ciphertext:
    for chunk in enc:
        ciphertext.write(chunk)
plaintext.close()

print("iv: " + str(binascii.hexlify(iv)))

