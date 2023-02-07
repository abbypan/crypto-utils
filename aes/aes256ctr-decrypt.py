#!/usr/bin/python
import secrets, binascii
import os
import sys
from buffered_encryption.aesctr import EncryptionIterator, ReadOnlyEncryptedFile

key = binascii.unhexlify(sys.argv[1])
iv =  binascii.unhexlify(sys.argv[2])

ciphertext_fname =  sys.argv[3]
plaintext_fname = sys.argv[4]

ciphertext = open(ciphertext_fname,"rb")

ef = ReadOnlyEncryptedFile(ciphertext,key,iv)

with open(plaintext_fname,"wb") as plaintext:
    for chunk in ef:
        plaintext.write(chunk)
ciphertext.close()


