#include <bls/bls384_256.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    int N = 5;
    int K = 3;
    int selectIds[] = { 0, 2, 4 };


    blsPublicKey mpk;
    blsId ids[N];
    blsSecretKey secs[N];
    blsPublicKey pubs[N];
    blsSignature sigs[N];

    mclSize n;
    mclSize maxBufSize = 400;
    char buf[maxBufSize];

    int r = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (r != 0) {
        printf("err blsInit %d\n", r);
        return 1;
    }

    char *msg = argv[1];
    const size_t msgSize = strlen(msg);

    for (int i = 0; i < N; i++) {
        blsIdSetInt(&ids[i], i + 1);
    }

    //cofficient
    blsSecretKey msk[K];
    for (int i = 0; i < K; i++) {
        blsSecretKeySetByCSPRNG(&msk[i]);
    }

    for (int i = 0; i < N; i++) {
        blsSecretKeyShare(&secs[i], msk, K, &ids[i]);

        n = blsSecretKeyGetHexStr(buf, maxBufSize, &secs[i]);
        printf("shared secret %d: %s\n", i, buf);
    }


    n = blsSecretKeyGetHexStr(buf, maxBufSize, &msk[0]);
    printf("msk: %s\n\n", buf);

    blsGetPublicKey(&mpk, &msk[0]);


    for (int i = 0; i < N; i++) {
        blsGetPublicKey(&pubs[i], &secs[i]);

        n = blsPublicKeyGetHexStr(buf, maxBufSize, &pubs[i]);
        printf("shared pub key %d: %s\n", i, buf);
    }

    n = blsPublicKeyGetHexStr(buf, maxBufSize, &mpk);
    printf("mpk: %s\n\n", buf);

    for (int i = 0; i < N; i++) {
        blsSign(&sigs[i], &secs[i], msg, msgSize);

        n = blsSignatureGetHexStr(buf, maxBufSize, &sigs[i]);
        printf("shared sig %d: %s\n", i, buf);
    }

    blsSignature subSigs[K];
    blsId subIds[K];
    for (int i = 0; i < K; i++) {
        subSigs[i] = sigs[selectIds[i]];
        subIds[i] = ids[selectIds[i]];
    }

    blsSignature sig;
    blsSignatureRecover(&sig, subSigs, subIds, K);

    n = blsSignatureGetHexStr(buf, maxBufSize, &sig);
    printf("\nrecover sig: %s\n", buf);

    /*int selectIdx[] = { 0, 1, 3 };*/
    /*for (int i = 0; i < K; i++) {*/
    /*subSigs[i] = sigs[selectIdx[i]];*/
    /*subIds[i] = ids[selectIdx[i]];*/
    /*}*/
    /*blsSignatureRecover(&sig, subSigs, subIds, K);*/
    /*n = blsSignatureGetHexStr(buf, maxBufSize, &sig);*/
    /*printf("recover sig x: %s\n", buf);*/

    printf("thresVerify: %d\n", blsVerify(&sig, &mpk, msg, msgSize));
}
