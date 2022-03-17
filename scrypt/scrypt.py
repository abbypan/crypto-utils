import pyscrypt

salt = b'644ad27f29fad36b80f9129501ad74705e675e205caff3d1520c41fec04c2551'
passwd = b'123456abcd'
key = pyscrypt.hash(passwd, salt, 2048, 8, 1, 32)
print("Derived key:", key.hex())
