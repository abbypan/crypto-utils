#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    // priv_key, tbs_file, output_signfile

    FILE *keyfile = fopen(argv[1], "r");

    EVP_PKEY *pkey = NULL;
    pkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    printf("\nRead Private Key:\n");
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);

    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();

    const EVP_MD *md_type;
    md_type = NULL; // no digest

    unsigned char sig[64];
    size_t siglen;

    unsigned char dgst[32];
    size_t dgstlen;
    FILE *dptr;

    dptr = fopen(argv[2],"rb");
    fread(dgst,sizeof(dgst), 1, dptr);
    dgstlen=sizeof(dgst);


    EVP_DigestSignInit(ctx, NULL, md_type, NULL, pkey);
    int r = EVP_DigestSign(ctx, sig, &siglen, dgst, dgstlen );
    printf("[sign] status: %d, siglen: %d, dgstlen %d\n", r, siglen, dgstlen);

    BIO *pubout;
    pubout = BIO_new_file(argv[3], "w+");
    BIO_write(pubout, sig, siglen);
    BIO_flush(pubout);

    return 0;
}
