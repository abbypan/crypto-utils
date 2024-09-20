#include <bls/bls384_256.h>
#include <string.h>
#include <stdio.h>

int main()
{
	blsSecretKey sec;
    mclSize n;
    mclSize maxBufSize = 128;
    char buf[maxBufSize];

	int ret = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (ret) {
		printf("err %d\n", ret);
		return 1;
	}
	blsSecretKeySetByCSPRNG(&sec);

    n = blsSecretKeyGetHexStr(buf, maxBufSize, &sec);
    printf("%s\n", buf);
}



