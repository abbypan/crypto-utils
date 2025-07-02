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
    // curve name, generator, ya, yb
    /*int nid = OBJ_sn2nid(argv[1]);*/
    int nid = OBJ_sn2nid("prime256v1");

    /*BIGNUM *pub_hex_bn = BN_new();*/
    /*BN_hex2bn(&pub_hex_bn,argv[2]); */

    BN_CTX *ctx = BN_CTX_new();

    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);

    EC_POINT* generator_point = EC_POINT_new(group);
    /*generator_point = EC_POINT_hex2point(group, argv[2], generator_point, ctx);*/
    generator_point = EC_POINT_hex2point(group, "04993b46e30ba9cfc3dc2d3ae2cf9733cf03994e74383c4e1b4a92e8d6d466b321c4a642979162fbde9e1c9a6180bd27a0594491e4c231f51006d0bf7992d07127", generator_point, ctx);
    char *point_compressed_hex = EC_POINT_point2hex(group, generator_point, POINT_CONVERSION_COMPRESSED, ctx);
    char *point_uncompressed_hex = EC_POINT_point2hex(group, generator_point, POINT_CONVERSION_UNCOMPRESSED, ctx);

    BIGNUM *ya = BN_new();
    /*BN_hex2bn(&ya,argv[3]); */
    BN_hex2bn(&ya,"c9e47ca5debd2285727af47e55f5b7763fa79719da428f800190cc6659b4eafb"); 
    EC_POINT* Ya = EC_POINT_new(group);
    EC_POINT_mul(group, Ya, NULL, generator_point, ya, ctx);
    char *Ya_hex = EC_POINT_point2hex(group, Ya, POINT_CONVERSION_UNCOMPRESSED, ctx);

    BIGNUM *yb = BN_new();
    /*BN_hex2bn(&yb,argv[4]); */
    BN_hex2bn(&yb,"a0b768ba7555621d133012d1dee27a0013c1bcfddd675811df12771e44d77b10"); 
    EC_POINT* Yb = EC_POINT_new(group);
    EC_POINT_mul(group, Yb, NULL, generator_point, yb, ctx);
    char *Yb_hex = EC_POINT_point2hex(group, Yb, POINT_CONVERSION_UNCOMPRESSED, ctx);

    EC_POINT* Ya_yb = EC_POINT_new(group);
    EC_POINT_mul(group, Ya_yb, NULL, Ya, yb, ctx);
    char *Ya_yb_hex = EC_POINT_point2hex(group, Ya_yb, POINT_CONVERSION_UNCOMPRESSED, ctx);

    EC_POINT* Yb_ya = EC_POINT_new(group);
    EC_POINT_mul(group, Yb_ya, NULL, Yb, ya, ctx);
    char *Yb_ya_hex = EC_POINT_point2hex(group, Yb_ya, POINT_CONVERSION_UNCOMPRESSED, ctx);

    BIGNUM *K_x = BN_new();
    BIGNUM *K_y = BN_new();
    EC_POINT_get_affine_coordinates(group, Ya_yb, K_x, K_y, ctx);


    /*EC_KEY_set_public_key(ec_key, generator_point);*/
    //POINT_CONVERSION_COMPRESSED = 2,
    //POINT_CONVERSION_UNCOMPRESSED = 4,
    //POINT_CONVERSION_HYBRID = 6
    /*EC_KEY* ec_key = EC_KEY_new();*/
    /*EC_KEY_set_group(ec_key, group);*/

    BIO    *out;
    out = BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    BIO_printf(out, "generator_point : 0x%s\n", point_compressed_hex );             
    BIO_printf(out, "generator_point : 0x%s\n", point_uncompressed_hex );             
    BIO_printf(out, "Ya : 0x%s\n", Ya_hex );             
    BIO_printf(out, "Yb : 0x%s\n", Yb_hex );             
    BIO_printf(out, "Ya_yb : 0x%s\n", Ya_yb_hex );             
    BIO_printf(out, "Yb_ya : 0x%s\n", Yb_ya_hex );             
    BIO_printf(out, "ya : 0x%s\n", BN_bn2hex(ya) );             
    BIO_printf(out, "yb : 0x%s\n", BN_bn2hex(yb) );             
    BIO_printf(out, "K_x : 0x%s\n", BN_bn2hex(K_x) );             


    /*EVP_PKEY *pkey = EVP_PKEY_new();*/
    /*EVP_PKEY_assign_EC_KEY(pkey, ec_key);*/

    /*printf("\nPUBKEY:\n");*/
    /*PEM_write_PUBKEY(stdout, pkey);*/

    /*BIO *pubout;*/
    /*pubout = BIO_new_file(argv[3], "w+");*/
    /*PEM_write_bio_PUBKEY(pubout, pkey);*/
    /*BIO_flush(pubout);*/

    return 0;
}
