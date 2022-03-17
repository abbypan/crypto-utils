#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>

#define BUFLEN 2048

int main(int argc, char *argv[]) {
    //pub file

    FILE *pubkeyfile = fopen(argv[1], "r");
    EVP_PKEY *pubkey = NULL;
    pubkey = PEM_read_PUBKEY(pubkeyfile, NULL, NULL, NULL);
    printf("\nRead Peer PUBKEY Key:\n");
    PEM_write_PUBKEY(stdout, pubkey);

    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pubkey);
    const EC_POINT *ec_point = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP *group=EC_KEY_get0_group(ec_key);

    char *point_compressed_hex = EC_POINT_point2hex(group, ec_point, POINT_CONVERSION_COMPRESSED, NULL);
    char *point_uncompressed_hex = EC_POINT_point2hex(group, ec_point, POINT_CONVERSION_UNCOMPRESSED, NULL);

    BIGNUM *x=BN_new();
    BIGNUM *y=BN_new();
    EC_POINT_get_affine_coordinates(group, ec_point, x, y, NULL);


    BIO    *out;
    out = BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    BIO_printf(out, "pub key x: 0x%s\n", BN_bn2hex(x) );             
    BIO_printf(out, "pub key y: 0x%s\n", BN_bn2hex(y) );             
    BIO_printf(out, "pub key : 0x%s\n", point_compressed_hex );             
    BIO_printf(out, "pub key : 0x%s\n", point_uncompressed_hex );             

    return 0;
}
