CC := g++
LDFLAGS += -I/usr/local/include -L/usr/local/lib
CFLAGS := -lopenabe


all: 
	$(CC) $(LDFLAGS) kp-abe-t-openabe.c -o kp-abe-t-openabe   $(CFLAGS)
	$(CC) $(LDFLAGS) cp-abe-t-openabe.c -o cp-abe-t-openabe   $(CFLAGS)


clean:
	/bin/rm kp-abe-t-openabe
	/bin/rm cp-abe-t-openabe
