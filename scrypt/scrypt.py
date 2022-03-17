import pyscrypt

salt = b'7c0533f1996f86dfaa19560d65cecd56bd7dd63fc864a150a694bc823877fb78'
passwd = b'82f4af28ec02a3a6bd0f43f2f76769b2'
key = pyscrypt.hash(passwd, salt, 2048, 8, 1, 32)
print("Derived key:", key.hex())
