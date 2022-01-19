#!/usr/bin/python
# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
import os
import hexdump

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

sharedinfo = b"ANSI X9.63 Example"

xkdf = X963KDF(
    algorithm=hashes.SHA256(),
    length=99,
    sharedinfo=sharedinfo,
)

key = xkdf.derive(b"input key")

hexdump.hexdump(key)

#xkdf = X963KDF(
    #algorithm=hashes.SHA256(),
    #length=99,
    #sharedinfo=sharedinfo,
#)
#xkdf.verify(b"input key", key)
