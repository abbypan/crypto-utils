#!/usr/bin/python
import secrets, binascii
import os
import sys
from buffered_encryption.aesgcm import EncryptionIterator, DecryptionIterator

key = binascii.unhexlify(sys.argv[1])
iv = binascii.unhexlify(sys.argv[2])
tag = binascii.unhexlify(sys.argv[3])
aad=binascii.unhexlify('')

ciphertext_fname =  sys.argv[4]
plaintext_fname = sys.argv[5]

ciphertext = open(ciphertext_fname,"rb")

dec = DecryptionIterator(ciphertext,key,aad,iv,tag)
with open(plaintext_fname,"wb") as decrypted:
    for chunk in dec:
        decrypted.write(chunk)

ciphertext.close()

print(dec)
