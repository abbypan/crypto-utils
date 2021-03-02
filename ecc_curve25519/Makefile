LIBRARIES = -lcrypto

all: ed25519_keypair ed25519_sign ed25519_verify

ed25519_keypair: ed25519_keypair.c
	gcc ed25519_keypair.c $(LIBRARIES) -o ed25519_keypair
	
ed25519_sign: ed25519_sign.c
	gcc ed25519_sign.c $(LIBRARIES) -o ed25519_sign

ed25519_verify: ed25519_verify.c
	gcc ed25519_verify.c $(LIBRARIES) -o ed25519_verify
	
x25519_keypair: x25519_keypair.c
	gcc x25519_keypair.c $(LIBRARIES) -o x25519_keypair
	
x25519_ecdh: x25519_ecdh.c
	gcc x25519_ecdh.c $(LIBRARIES) -o x25519_ecdh
