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
    // curve name, point_hex , pub file
    int nid = OBJ_sn2nid(argv[1]);

    BIGNUM *pub_hex_bn = BN_new();
    BN_hex2bn(&pub_hex_bn,argv[2]); 

    BN_CTX *ctx = BN_CTX_new();

    EC_KEY* ec_key = EC_KEY_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    EC_KEY_set_group(ec_key, group);

    EC_POINT* ec_pub_point = EC_POINT_new(group);
    ec_pub_point = EC_POINT_hex2point(group, argv[2], ec_pub_point, ctx);

    EC_KEY_set_public_key(ec_key, ec_pub_point);

    //POINT_CONVERSION_COMPRESSED = 2,
    //POINT_CONVERSION_UNCOMPRESSED = 4,
    //POINT_CONVERSION_HYBRID = 6
    char *point_compressed_hex = EC_POINT_point2hex(group, ec_pub_point, POINT_CONVERSION_COMPRESSED, ctx);
    char *point_uncompressed_hex = EC_POINT_point2hex(group, ec_pub_point, POINT_CONVERSION_UNCOMPRESSED, ctx);

    BIO    *out;
    out = BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    BIO_printf(out, "pub key : 0x%s\n", point_compressed_hex );             
    BIO_printf(out, "pub key : 0x%s\n", point_uncompressed_hex );             


    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    printf("\nPUBKEY:\n");
    PEM_write_PUBKEY(stdout, pkey);

    BIO *pubout;
    pubout = BIO_new_file(argv[3], "w+");
    PEM_write_bio_PUBKEY(pubout, pkey);
    BIO_flush(pubout);

    return 0;
}
