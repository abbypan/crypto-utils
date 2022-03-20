#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html

void print_bn(BIO *out, char* name, BIGNUM *u){
    BIO_printf(out, "%s: 0x%s = %s\n", name, BN_bn2hex(u), BN_bn2dec(u) );             
}

int sgn0_m_eq_1 (BIGNUM *x) {
    BN_ULONG r = BN_mod_word(x, 2);
    return (int) r;
}

BIGNUM* CMOV(BIGNUM *a, BIGNUM *b, int c){
    if(c){
        return b;
    }
    return a;
}

int map_to_curve_simple_swu_optimized(BIGNUM *c1, BIGNUM *c2, BIGNUM *a, BIGNUM *b, BIGNUM *p, BIGNUM *z, BIGNUM *u, BIGNUM *x, BIGNUM *y, BN_CTX *ctx){
    //F.2 sswu
    BIGNUM *tv1, *tv2, *x1, *gx1, *gx2, *x2, *y2;

    tv1 = BN_new();
    BN_mod_sqr(tv1, u, p, ctx);
    BN_mod_mul(tv1, tv1, z, p, ctx);

    tv2 = BN_new();
    BN_mod_sqr(tv2, tv1, p, ctx);

    x1 = BN_new();
    BN_mod_add(x1, tv1, tv2, p, ctx);
    BN_mod_inverse(x1, x1, p, ctx);

    int e1 = BN_is_zero(x1); 
    BN_add_word(x1, 1);
    x1 = CMOV(x1, c2, e1);
    BN_mod_mul(x1, x1, c1, p, ctx);

    gx1 = BN_new();
    BN_mod_sqr(gx1, x1, p, ctx);
    BN_mod_add(gx1, gx1, a, p, ctx);
    BN_mod_mul(gx1, gx1, x1, p, ctx);
    BN_mod_add(gx1, gx1, b, p, ctx);

    x2 = BN_new();
    BN_mod_mul(x2, tv1, x1, p, ctx);
    BN_mod_mul(tv2, tv1, tv2, p, ctx);

    gx2 = BN_new();
    BN_mod_mul(gx2, gx1, tv2, p, ctx);

    BIGNUM *e2_bn = BN_new();
    BIGNUM *e2_ret = BN_mod_sqrt(e2_bn, gx1, p, ctx);
    BN_copy(x, CMOV(x2, x1, e2_ret!=NULL));

    y2 = CMOV(gx2, gx1, e2_ret!=NULL);
    BN_mod_sqrt(y, y2, p, ctx);

    if(sgn0_m_eq_1(u) != sgn0_m_eq_1(y)){
        BN_set_negative(y, 1);
        BN_mod_add(y, y, p, p, ctx);
    }

    BN_free(tv1);
    BN_free(tv2);
    BN_free(x1);
    BN_free(gx1);
    BN_free(x2);
    BN_free(gx2);
    BN_free(e2_bn);

    return 1;
}

int map_to_curve_simple_swu(BIGNUM *a, BIGNUM *b, BIGNUM *p, BIGNUM *z, BIGNUM *u, BIGNUM *x, BIGNUM *y, BN_CTX *ctx){
    //6.6.2 sswu
    BIGNUM *tmp1 = BN_new();
    BN_mod(tmp1, u, p, ctx);
    BN_mod_sqr(tmp1, tmp1, p, ctx);
    BN_mod_mul(tmp1, tmp1, z, p, ctx);

    BIGNUM *tv1 = BN_new();
    BN_copy(tv1, tmp1);
    BN_mod_sqr(tv1, tv1, p, ctx);
    BN_mod_add(tv1, tv1, tmp1, p, ctx);
    BN_mod_inverse(tv1, tv1, p, ctx);

    /*BIGNUM *one = BN_new();*/
    /*BN_hex2bn(&one,"1");*/

    BN_copy(x, tv1);
    /*BN_mod_add(x, x, one, p, ctx);*/
    BN_add_word(x, 1);
    BN_mod_mul(x, x, b, p, ctx);
    BN_set_negative(x, 1);

    BIGNUM *a_inv = BN_new();
    BN_mod_inverse(a_inv, a, p, ctx);
    BN_mod_mul(x, x, a_inv, p, ctx);

    if(BN_is_zero(tv1)){
        BN_copy(x, z);
        BN_mod_inverse(x, x, p,ctx);
        BN_mod_mul(x, x, b, p, ctx);
        BN_mod_mul(x, x, a_inv, p, ctx);
    }

    BIGNUM *gx = BN_new();
    BN_copy(gx, x);
    BN_mod_sqr(gx, gx, p, ctx);
    BN_mod_add(gx, gx, a, p, ctx);
    BN_mod_mul(gx, gx, x, p, ctx);
    BN_mod_add(gx, gx, b, p, ctx);

    BN_mod_sqrt(y, gx, p, ctx);

    BIGNUM *y2 = BN_new();
    BN_mod_sqr(y2, y, p, ctx);
    if(BN_cmp(y2, gx)!=0){
        BN_mod_mul(x, x, tmp1, p, ctx);

        BN_copy(gx, x);
        BN_mod_sqr(gx, gx, p, ctx);
        BN_mod_add(gx, gx, a, p, ctx);
        BN_mod_mul(gx, gx, x, p, ctx);
        BN_mod_add(gx, gx, b, p, ctx);

        BN_mod_sqrt(y, gx, p, ctx);
        BN_mod_sqr(y2, y, p, ctx);
        if( BN_cmp(y2, gx)!=0 ){
            return 0;
        }
    }

    if(sgn0_m_eq_1(u) != sgn0_m_eq_1(y)){
        BN_set_negative(y, 1);
        BN_mod_add(y, y, p, p, ctx);
    }

    BN_free(tmp1);
    BN_free(tv1);
    /*BN_free(one);*/
    BN_free(a_inv);
    BN_free(gx);
    BN_free(y2);

    return 1;
}

int clear_cofactor(EC_GROUP *group, EC_POINT *P, EC_POINT *Q, BN_CTX* ctx){
    const BIGNUM *cofactor = EC_GROUP_get0_cofactor(group);
    EC_POINT_mul(group, P, NULL, Q, cofactor, ctx);
    return 1;
}

/*EC_POINT* map_to_curve(EC_GROUP *group, BIGNUM *u, BN_CTX *ctx){*/
    /*BIGNUM *p, *a, *b;*/
    /*EC_GROUP_get_curve(group, p, a, b, ctx);*/

/*}*/

BIGNUM* find_z_sswu(char* sn){
    BIGNUM *z = BN_new();
    if(strcmp(sn, "prime256v1")==0){
        BN_dec2bn(&z,"-10"); // dec to binary
        return z;
    }
    BN_free(z);
    return NULL;
}

EC_POINT* map_to_curve_sswu(EC_GROUP *group, BIGNUM *c1, BIGNUM *c2, BIGNUM *a, BIGNUM *b, BIGNUM *p, BIGNUM *z, BIGNUM *u, BN_CTX *ctx){
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    /*map_to_curve_simple_swu(a, b, p, z, u, x, y, ctx);*/
    map_to_curve_simple_swu_optimized(c1, c2, a, b, p, z, u, x, y, ctx);

    EC_POINT *Q = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, Q, x, y, ctx);
    return Q;
}

EC_POINT* hash_to_curve_sswu(EC_GROUP *group, BIGNUM *c1, BIGNUM *c2, BIGNUM *a, BIGNUM *b, BIGNUM *p, BIGNUM *z, BIGNUM *u0, BIGNUM *u1, BN_CTX *ctx){
    EC_POINT *Q0 = map_to_curve_sswu(group, c1, c2, a, b, p, z, u0, ctx);
    EC_POINT *Q1 = map_to_curve_sswu(group, c1, c2, a, b, p, z, u1, ctx);
    EC_POINT *P_raw = EC_POINT_new(group);
    EC_POINT_add(group, P_raw, Q0, Q1, ctx);
    EC_POINT *P = EC_POINT_new(group);
    clear_cofactor(group, P, P_raw, ctx);
    EC_POINT_free(P_raw);
    return P;
}

int main(int argc, char* argv[])
{
    int nid = OBJ_sn2nid(argv[1]);
    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);

    BIGNUM *a, *b, *p, *h, *z, *c1, *c2, *u0, *u1,  *x, *y;
    BN_CTX *ctx;

    BIO    *out;
    out = BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);

    ctx = BN_CTX_new();

    //G	(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
    //n	0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    
    h = BN_new();
    BN_dec2bn(&h,"1"); //dec to binary

    a = BN_new();
    BN_dec2bn(&a,"-3"); //dec to binary

    b = BN_new();
    BN_hex2bn(&b,"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"); 

    p = BN_new();
    BN_hex2bn(&p,"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

    z = BN_new();
    BN_dec2bn(&z,"-10"); // dec to binary

    c1 = BN_new();
    BN_mod_inverse(c1, a, p, ctx);
    BN_mod_mul(c1, c1, b, p, ctx);
    BN_set_negative(c1, 1);

    c2 = BN_new();
    BN_mod_inverse(c2, z, p, ctx);
    BN_set_negative(c2, 1);

    print_bn(out, "a", a);                                                                                       
    print_bn(out, "b", b);                                                                                       
    print_bn(out, "p", p);                                                                                       
    print_bn(out, "z", z);                                                                                       
    print_bn(out, "c1", c1);
    print_bn(out, "c2", c2);

    //calc
    u0 = BN_new();
    BN_hex2bn(&u0,"ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009"); 

    /*x = BN_new();*/
    /*y = BN_new();*/

    /*map_to_curve_simple_swu(a, b, p, z, u, x, y, ctx);*/
    /*map_to_curve_simple_swu_optimized(c1, c2, a, b, p, z, u, x, y, ctx);*/

    /*EC_POINT *Q = EC_POINT_new(group);*/
    /*EC_POINT_set_affine_coordinates(group, Q, x, y, ctx);*/

    EC_POINT *Q0 = map_to_curve_sswu(group, c1, c2, a, b, p, z, u0, ctx);
    char *Q0_uncompressed_hex = EC_POINT_point2hex(group, Q0, POINT_CONVERSION_UNCOMPRESSED, ctx);
    BIO_printf(out, "map to curve:\nu0: %s\nQ0: %s\n", BN_bn2hex(u0), Q0_uncompressed_hex);

    u1 = BN_new();
    BN_hex2bn(&u1,"8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a"); 
    EC_POINT *Q1 = map_to_curve_sswu(group, c1, c2, a, b, p, z, u1, ctx);
    char *Q1_uncompressed_hex = EC_POINT_point2hex(group, Q1, POINT_CONVERSION_UNCOMPRESSED, ctx);
    BIO_printf(out, "map to curve:\nu1: %s\nQ1: %s\n", BN_bn2hex(u1), Q1_uncompressed_hex);

    EC_POINT *P = hash_to_curve_sswu(group,  c1, c2, a, b, p, z, u0, u1, ctx);
    char *P_uncompressed_hex = EC_POINT_point2hex(group, P, POINT_CONVERSION_UNCOMPRESSED, ctx);
    BIO_printf(out, "hash to curve:\nu0: %s\nu1: %s\nP: %s\n",BN_bn2hex(u0),  BN_bn2hex(u1), P_uncompressed_hex);

    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_free(z);
    BN_free(c1);
    BN_free(c2);
    BN_CTX_free(ctx);
    BIO_free(out);
    return 0;
}


