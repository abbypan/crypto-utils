CC := gcc
CFLAGS := -loqs -lcrypto -pthread 


all: 
	gcc oqs-kem.c -o oqs-kem   $(CFLAGS)
	gcc oqs-sig.c -o oqs-sig   $(CFLAGS)
 

clean:
	/bin/rm oqs-kem
	/bin/rm oqs-sig
