from pbkdf2 import PBKDF2
from hexdump import dump
from Crypto.Hash import HMAC, SHA256

password = '123456'
salt = bytes.fromhex('b698314b0d68bcbd')

key = PBKDF2(password, salt, iterations=2048, digestmodule=SHA256, macmodule=HMAC)
key_bin = key.read(32)

print(dump(key_bin))
#F6 8B 53 86 DE 3A 8D 63 35 84 69 50 54 4D 29 A5 5A D3 32 8D EA 17 68 53 04 D7 82 28 48 AE C5 34
