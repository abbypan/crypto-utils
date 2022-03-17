LIBRARIES = -lcrypto

all: ecdh x25519_keypair ecdh_ephemeral_key

x25519_keypair: x25519_keypair.c
	gcc x25519_keypair.c $(LIBRARIES) -o x25519_keypair
	gcc x448_keypair.c $(LIBRARIES) -o x448_keypair
	
ecdh: ecdh.c
	gcc ecdh.c $(LIBRARIES) -o ecdh
	
ecdh_ephemeral_key: ecdh_ephemeral_key.c
	gcc ecdh_ephemeral_key.c $(LIBRARIES) -o ecdh_ephemeral_key
