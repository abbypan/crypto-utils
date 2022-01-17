#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
//#include <openssl/encoder.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>

#define BUFLEN 2048

void hexdump(unsigned char *info, unsigned char *buf, const int num)
{
    int i;
    printf("\n%s, %d\n", info, num);

    for(i = 0; i < num; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");

    for(i = 0; i < num; i++)
    {
        printf("%02x ", buf[i]);
        if ((i+1)%8 == 0)
            printf("\n");
    }
    printf("\n");
    return;
}

//openssl demos/pkey/EVP_PKEY_EC_keygen.c
EVP_PKEY* do_ec_keygen(int nid)
{

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

void write_private_key(char* fname, EVP_PKEY* pkey){
    BIO *privout;
    privout = BIO_new_file(fname, "w+");
    PEM_write_bio_PrivateKey(privout, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_flush(privout);
}

void write_public_key(char* fname, EVP_PKEY* pkey){
    BIO *pubout;
    pubout = BIO_new_file(fname, "w+");
    PEM_write_bio_PUBKEY(pubout, pkey);
    BIO_flush(pubout);
}

int main(int argc, char *argv[]) {
    // local_priv_key, peer_pub_key, Z = ecdh

    printf("\nGenerate Private Key:\n");
    EVP_PKEY *pkey = do_ec_keygen(NID_X9_62_prime256v1);
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    write_private_key("ephemeral_a_private.pem", pkey);

    printf("\nExport Public Key:\n");
    unsigned char *publicKey = NULL;
    size_t publicLen = 0;
    publicLen = i2d_PUBKEY(pkey, &publicKey);

    EVP_PKEY *pubKey = NULL;
    pubKey = d2i_PUBKEY(&pubKey, (const unsigned char **) &publicKey, publicLen);
    PEM_write_PUBKEY(stdout, pubKey);
    write_public_key("ephemeral_a_public.pem", pubKey);

    printf("\nGenerate Peer Private Key:\n");
    EVP_PKEY *peer_pkey = do_ec_keygen(NID_X9_62_prime256v1);
    PEM_write_PrivateKey(stdout, peer_pkey, NULL, NULL, 0, NULL, NULL);
    write_private_key("ephemeral_b_private.pem", peer_pkey);

    printf("\nExport Peer Public Key:\n");
    unsigned char *peer_publicKey = NULL;
    size_t peer_publicLen = 0;
    peer_publicLen = i2d_PUBKEY(peer_pkey, &peer_publicKey);

    EVP_PKEY *peer_pubKey = NULL;
    peer_pubKey = d2i_PUBKEY(&peer_pubKey, (const unsigned char **) &peer_publicKey, peer_publicLen);
    PEM_write_PUBKEY(stdout, peer_pubKey);
    write_public_key("ephemeral_b_public.pem", peer_pubKey);

    EVP_PKEY_CTX *ctx;
    unsigned char *z;
    size_t zlen;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    EVP_PKEY_derive_init(ctx);

    EVP_PKEY_derive_set_peer(ctx, peer_pubKey);

    EVP_PKEY_derive(ctx, NULL, &zlen);

    z = OPENSSL_malloc(zlen);

    EVP_PKEY_derive(ctx, z, &zlen);

    hexdump("Z", z, zlen);

    return 0;
}
