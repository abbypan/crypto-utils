LIBRARIES = -lcrypto

all: eddsa_sign eddsa_verify ec_keypair ec_priv_key ec_pub_key

ec_priv_key: ec_priv_key.c
	gcc ec_priv_key.c $(LIBRARIES) -o ec_priv_key

ec_pub_key: ec_pub_key.c
	gcc ec_pub_key.c $(LIBRARIES) -o ec_pub_key

ec_keypair: ec_keypair.c
	gcc ec_keypair.c $(LIBRARIES) -o ec_keypair
	
eddsa_sign: eddsa_sign.c
	gcc eddsa_sign.c $(LIBRARIES) -o eddsa_sign

eddsa_verify: eddsa_verify.c
	gcc eddsa_verify.c $(LIBRARIES) -o eddsa_verify
