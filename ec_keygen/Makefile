LIBRARIES = -lcrypto

all: eddsa_sign eddsa_verify ec_keypair ec_priv_key ec_pub_key ec_pub_key2 ec_pub_key3 ec_pub_key_read hash_to_curve cpace_calc_K

ec_priv_key: ec_priv_key.c
	gcc ec_priv_key.c $(LIBRARIES) -o ec_priv_key

ec_pub_key: ec_pub_key.c
	gcc ec_pub_key.c $(LIBRARIES) -o ec_pub_key
	
ec_pub_key2: ec_pub_key2.c
	gcc ec_pub_key2.c $(LIBRARIES) -o ec_pub_key2
	
ec_pub_key3: ec_pub_key3.c
	gcc ec_pub_key3.c $(LIBRARIES) -o ec_pub_key3

ec_keypair: ec_keypair.c
	gcc ec_keypair.c $(LIBRARIES) -o ec_keypair
	
eddsa_sign: eddsa_sign.c
	gcc eddsa_sign.c $(LIBRARIES) -o eddsa_sign

eddsa_verify: eddsa_verify.c
	gcc eddsa_verify.c $(LIBRARIES) -o eddsa_verify

ec_pub_key_read: ec_pub_key_read.c
	gcc ec_pub_key_read.c $(LIBRARIES) -o ec_pub_key_read

hash_to_curve: hash_to_curve.c
	gcc hash_to_curve.c $(LIBRARIES) -o hash_to_curve

cpace_calc_K: cpace_calc_K.c
	gcc cpace_calc_K.c $(LIBRARIES) -o cpace_calc_K

clean:
	rm eddsa_sign eddsa_verify ec_keypair ec_priv_key ec_pub_key ec_pub_key2 ec_pub_key3 ec_pub_key_read hash_to_curve cpace_calc_K

