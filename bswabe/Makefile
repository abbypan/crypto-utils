CC := gcc
LDFLAGS += -I/usr/local/include -L/usr/local/lib
CFLAGS := -lbswabe -lpbc -lgmp -lcrypto `pkg-config --cflags --libs glib-2.0`


all: 
	$(CC) $(LDFLAGS) bsw07.c -o bsw07   $(CFLAGS)
 

clean:
	/bin/rm bsw07
