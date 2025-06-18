#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


unsigned char* hex2bin(const char *hexstr) {

    size_t hexstrLen = strlen(hexstr);
    size_t bytesLen = hexstrLen / 2;
    unsigned char* binstr = (unsigned char*) malloc(bytesLen);

    BIGNUM *a = BN_new();
    BN_hex2bn(&a, hexstr);
    BN_bn2bin(a, binstr);

    return binstr;
}

void main(int argc, char *argv[]) {

    unsigned char *hex = argv[1];
    unsigned char *bin = hex2bin(hex);
    fprintf(stdout, "%s", bin);
}
