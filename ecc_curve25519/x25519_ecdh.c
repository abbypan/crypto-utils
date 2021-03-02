#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>

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

int main(int argc, char *argv[]) {
    // local_priv_key, peer_pub_key, Z = ecdh

    FILE *keyfile = fopen(argv[1], "r");
    EVP_PKEY *pkey = NULL;
    pkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
    printf("\nRead Local Private Key:\n");
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);

    FILE *peer_pubkeyfile = fopen(argv[2], "r");
    EVP_PKEY *peer_pubkey = NULL;
    peer_pubkey = PEM_read_PUBKEY(peer_pubkeyfile, NULL, NULL, NULL);
    printf("\nRead Peer PUBKEY Key:\n");
    PEM_write_PUBKEY(stdout, peer_pubkey);


    EVP_PKEY_CTX *ctx;
    unsigned char *z;
    size_t zlen;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    EVP_PKEY_derive_init(ctx);

    EVP_PKEY_derive_set_peer(ctx, peer_pubkey);

    EVP_PKEY_derive(ctx, NULL, &zlen);

    z = OPENSSL_malloc(zlen);

    EVP_PKEY_derive(ctx, z, &zlen);

    hexdump("Z", z, zlen);

    return 0;
}
