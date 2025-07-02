LIBRARIES = -lcrypto -lssl

all: ecdh x25519_keypair ecdh_ephemeral_key

x25519_keypair: x25519_keypair.c
	gcc x25519_keypair.c $(LIBRARIES) -o x25519_keypair
	gcc x448_keypair.c $(LIBRARIES) -o x448_keypair
	
ecdh: ecdh.c
	gcc ecdh.c $(LIBRARIES) -o ecdh
	
ecdh_ephemeral_key: ecdh_ephemeral_key.c
	gcc ecdh_ephemeral_key.c $(LIBRARIES) -o ecdh_ephemeral_key

ecies: ecies_enc.c ecies_dec.c
	gcc ecies_enc.c $(LIBRARIES) -o ecies_enc
	gcc ecies_dec.c $(LIBRARIES) -o ecies_dec

aes-gcm: aes-gcm-enc.c aes-gcm-dec.c
	gcc aes-gcm-enc.c $(LIBRARIES) -o aes-gcm-enc
	gcc aes-gcm-dec.c $(LIBRARIES) -o aes-gcm-dec

random: random.c
	gcc random.c $(LIBRARIES) -o random
