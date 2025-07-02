#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdio.h>

void hexdump(unsigned char *info, unsigned char *buf, const int num)
{
    int i;
    printf("\n%s, %d\n", info, num);

    for(i = 0; i < num; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");

    for(i = 0; i < num; i++)
    {
        printf("%02x ", buf[i]);
        if ((i+1)%8 == 0)
            printf("\n");
    }
    printf("\n");
    return;
}

int gen_random(unsigned char **r, int len) {

	*r = OPENSSL_malloc(len);
	if (RAND_bytes(*r, len) != 1) {
		OPENSSL_free(*r);
		return 0;
	}

	return len;
}

void main(int argc, char *argv[]){
	unsigned char *r = NULL;
	int len =12;
	sscanf(argv[1], "%d", &len);
	gen_random(&r, len);
	hexdump("r", r, len);
}
