LIBRARIES = -lcrypto -lssl

all: random

random: random.c
	gcc random.c $(LIBRARIES) -o random

clean:
	rm random
