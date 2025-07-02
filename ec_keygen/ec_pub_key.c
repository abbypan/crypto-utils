#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/objects.h>

int main(int argc, char* argv[]) {
    // pubate_key_hex, pub_key_file, pub_key_file
    int nid = OBJ_sn2nid(argv[1]);

    BIGNUM *pub = BN_new();
    BN_hex2bn(&pub,argv[2]); 

    BIO    *out;
    out = BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    BIO_printf(out, "pub key: 0x%s\n", BN_bn2hex(pub) );             

    int tolen = BN_num_bytes(pub);
    unsigned char *to = malloc(tolen);
    BN_bn2bin(pub, to);

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(nid, NULL, to, tolen);

    printf("\nPUBKEY:\n");
    PEM_write_PUBKEY(stdout, pkey);

    BIO *pubout;
    pubout = BIO_new_file(argv[3], "w+");
    PEM_write_bio_PUBKEY(pubout, pkey);
    BIO_flush(pubout);

    return 0;
}
