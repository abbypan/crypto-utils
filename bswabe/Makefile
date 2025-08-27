CC := gcc
LDFLAGS += -I/usr/local/include -L/usr/local/lib
CFLAGS := -lbswabe -lpbc -lgmp -lcrypto `pkg-config --cflags --libs glib-2.0`


all: 
	$(CC) $(LDFLAGS) cp-abe-t.c -o cp-abe-t   $(CFLAGS)
 

clean:
	/bin/rm cp-abe-t
