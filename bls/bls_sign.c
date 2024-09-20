#include <bls/bls384_256.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    blsSecretKey sec;
    blsSignature sig;
    char *sechex = argv[1];
    char *msg = argv[2];
    const size_t msgSize = strlen(msg);
    mclSize n;
    mclSize maxBufSize = 400;
    char buf[maxBufSize];
    int ret = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (ret) {
        printf("err %d\n", ret);
        return 1;
    }
    blsSecretKeySetHexStr(&sec, sechex, strlen(sechex));
    blsSign(&sig, &sec, msg, msgSize);
    n = blsSignatureGetHexStr(buf, maxBufSize, &sig);
    printf("sig (%d): %s\n", n, buf);
}
