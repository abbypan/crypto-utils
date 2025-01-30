from pbkdf2 import PBKDF2
from hexdump import dump
from Crypto.Hash import HMAC, SHA256

password = 'justfortest'
salt = bytes.fromhex('b698314b0d68bcbd')

key = PBKDF2(password, salt, iterations=2048, digestmodule=SHA256, macmodule=HMAC)
key_bin = key.read(32)

print(dump(key_bin))
