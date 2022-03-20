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
    // private_key_hex, priv_key_file, pub_key_file

    // https://github.com/openssl/openssl/blob/master/crypto/objects/obj_dat.h
    int nid = OBJ_sn2nid(argv[1]);

    BIGNUM *priv = BN_new();
    BN_hex2bn(&priv,argv[2]); 

    BIO    *out;
    out = BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    BIO_printf(out, "priv key: 0x%s\n", BN_bn2hex(priv) );             

    int tolen = BN_num_bytes(priv);
    unsigned char *to = malloc(tolen);
    BN_bn2bin(priv, to);

    /*EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, to, tolen);*/
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(nid, NULL, to, tolen);

    printf("\nPRIVATE KEY:\n");
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    printf("\nPUBKEY:\n");
    PEM_write_PUBKEY(stdout, pkey);

    BIO *privout;
    privout = BIO_new_file(argv[3], "w+");
    PEM_write_bio_PrivateKey(privout, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_flush(privout);

    BIO *pubout;
    pubout = BIO_new_file(argv[4], "w+");
    PEM_write_bio_PUBKEY(pubout, pkey);
    BIO_flush(pubout);

    return 0;
}
