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
    // curve name, x, y , pub file
    int nid = OBJ_sn2nid(argv[1]);
    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *pub_x = BN_new();
    BN_hex2bn(&pub_x,argv[2]); 
    
    BIGNUM *pub_y = BN_new();
    BN_hex2bn(&pub_y,argv[3]); 
    

    EC_POINT* ec_pub_point = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, ec_pub_point, pub_x, pub_y, ctx);

    //POINT_CONVERSION_COMPRESSED = 2,
    //POINT_CONVERSION_UNCOMPRESSED = 4,
    //POINT_CONVERSION_HYBRID = 6
    char *point_compressed_hex = EC_POINT_point2hex(group, ec_pub_point, POINT_CONVERSION_COMPRESSED, ctx);
    char *point_uncompressed_hex = EC_POINT_point2hex(group, ec_pub_point, POINT_CONVERSION_UNCOMPRESSED, ctx);

    BIO    *out;
    out = BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);
    /*BIO_printf(out, "pub key x: 0x%s\n", BN_bn2hex(pub_x) );             */
    /*BIO_printf(out, "pub key y: 0x%s\n", BN_bn2hex(pub_y) );             */
    BIO_printf(out, "pub key : 0x%s\n", point_compressed_hex );             
    BIO_printf(out, "pub key : 0x%s\n", point_uncompressed_hex );             

    EC_KEY* ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, group);
    EC_KEY_set_public_key(ec_key, ec_pub_point);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    printf("\nPUBKEY:\n");
    PEM_write_PUBKEY(stdout, pkey);

    BIO *pubout;
    pubout = BIO_new_file(argv[4], "w+");
    PEM_write_bio_PUBKEY(pubout, pkey);
    BIO_flush(pubout);

    return 0;
}
