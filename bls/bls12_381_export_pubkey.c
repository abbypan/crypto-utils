#include <bls/bls384_256.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	blsSecretKey sec;
	blsPublicKey pub;
	blsSignature sig;
    mclSize n;
    mclSize maxBufSize = 400;
    char buf[maxBufSize];

    char *sechex = argv[1];
	int ret = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (ret) {
		printf("err %d\n", ret);
		return 1;
	}
    blsSecretKeySetHexStr(&sec, sechex, strlen(sechex));
	blsGetPublicKey(&pub, &sec);
    n = blsPublicKeyGetHexStr(buf, maxBufSize, &pub);
    printf("%s\n", buf);
}
