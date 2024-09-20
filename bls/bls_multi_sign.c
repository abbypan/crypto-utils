#include <bls/bls384_256.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    int N = 20;
    blsPublicKey pubVec[N];
    blsSignature sigVec[N];
    blsPublicKey aggPub;
    blsSignature aggSig;
    blsSecretKey sec;

    mclSize n;
    mclSize maxBufSize = 400;
    char buf[maxBufSize];

    char *msg = argv[1];
    const size_t msgSize = strlen(msg);

    int ret = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (ret) {
        printf("err %d\n", ret);
        return 1;
    }


    size_t j;
    for(j=0; j<N && j<argc-2;j++){
        /*memset(&sec, -1, sizeof(sec));*/
        blsSecretKeySetHexStr(&sec, argv[j+2], strlen(argv[j+2]));
        blsGetPublicKey(&pubVec[j], &sec);
        blsSign(&sigVec[j], &sec, msg, msgSize);


        /*memset(&buf, -1, sizeof(buf));*/
        n = blsPublicKeyGetHexStr(buf, maxBufSize, &pubVec[j]);
        printf("sec (%d): %s\npub (%d): %s\n", sizeof(sec), argv[j+2], sizeof(pubVec[j]), buf);

        /*memset(&buf, -1, sizeof(buf));*/
        n = blsSignatureGetHexStr(buf, maxBufSize, &sigVec[j]);
        printf("sig (%d): %s\n\n", sizeof(sigVec[j]), buf);
    }


    /*memset(&aggPub, -1, sizeof(aggPub));*/
    /*memset(&aggSig, -1, sizeof(aggSig));*/
    blsMultiAggregatePublicKey(&aggPub, pubVec, j);
    blsMultiAggregateSignature(&aggSig, sigVec, pubVec, j);

    /*memset(&buf, -1, sizeof(buf));*/
    n = blsPublicKeyGetHexStr(buf, maxBufSize, &aggPub);
    printf("aggPub (%d): %s\n", sizeof(aggPub), buf);

    /*memset(&buf, -1, sizeof(buf));*/
    n = blsSignatureGetHexStr(buf, maxBufSize, &aggSig);
    printf("aggSig (%d): %s\n", sizeof(aggSig), buf);

	printf("aggVerify: %d\n", blsVerify(&aggSig, &aggPub, msg, msgSize));
}
