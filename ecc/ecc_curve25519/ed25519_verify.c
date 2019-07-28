#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    // pub_key, tbs_file, signfile

    FILE *pubkeyfile = fopen(argv[1], "r");

    EVP_PKEY *pubkey = NULL;
    pubkey = PEM_read_PUBKEY(pubkeyfile, NULL, NULL, NULL);
    printf("\nRead PUBKEY Key:\n");
    PEM_write_PUBKEY(stdout, pubkey);


    unsigned char sig[64];
    size_t siglen;
    FILE *pubtr;

    pubtr = fopen(argv[3],"rb");
    fread(sig,sizeof(sig), 1, pubtr);
    siglen=sizeof(sig);


    EVP_MD_CTX *pubctx;
    pubctx = EVP_MD_CTX_new();

    const EVP_MD *md_type;
    md_type = NULL; // no digest

    EVP_DigestVerifyInit(pubctx, NULL, NULL, NULL, pubkey);

    unsigned char dgst[32];
    size_t dgstlen;
    FILE *dptr;

    dptr = fopen(argv[2],"rb");
    fread(dgst,sizeof(dgst), 1, dptr);
    dgstlen=sizeof(dgst);

    int r=EVP_DigestVerify(pubctx, sig, siglen, dgst, dgstlen);

    printf("[verify] status: %d, siglen: %d, dgstlen: %d\n", r, siglen, dgstlen);
    return 0;

}
