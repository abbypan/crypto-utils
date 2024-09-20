#include <bls/bls384_256.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	blsPublicKey pub;
	blsSignature sig;
    char *pubhex = argv[1];
    char *msg = argv[2];
    char *sighex = argv[3];
	const size_t msgSize = strlen(msg);
	int ret = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (ret) {
		printf("err %d\n", ret);
		return 1;
	}
    blsSignatureSetHexStr(&sig, sighex, strlen(sighex));
    blsPublicKeySetHexStr(&pub, pubhex, strlen(pubhex));
	printf("verify %d\n", blsVerify(&sig, &pub, msg, msgSize));
}
