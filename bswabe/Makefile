CC := gcc
LDFLAGS += -I/usr/local/include -L/usr/local/lib
CFLAGS := -lbswabe -lpbc -lgmp -lcrypto `pkg-config --cflags --libs glib-2.0`


all: 
	$(CC) $(LDFLAGS) bsw17.c -o bsw17   $(CFLAGS)
 

clean:
	/bin/rm bsw17
