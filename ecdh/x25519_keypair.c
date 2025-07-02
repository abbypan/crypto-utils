#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

int main(int argc, char* argv[]) {
    // priv_key_file, pub_key_file

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    printf("\nPRIVATE KEY:\n");
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    printf("\nPUBKEY:\n");
    PEM_write_PUBKEY(stdout, pkey);

    BIO *privout;
    privout = BIO_new_file(argv[1], "w+");
    PEM_write_bio_PrivateKey(privout, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_flush(privout);

    BIO *pubout;
    pubout = BIO_new_file(argv[2], "w+");
    PEM_write_bio_PUBKEY(pubout, pkey);
    BIO_flush(pubout);

    return 0;
}
