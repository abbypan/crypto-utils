LIBRARIES = -lcrypto -lssl


ecies: ecies_enc.c ecies_dec.c
	gcc ecies_enc.c $(LIBRARIES) -o ecies_enc
	gcc ecies_dec.c $(LIBRARIES) -o ecies_dec

