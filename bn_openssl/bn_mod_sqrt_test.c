#include <openssl/bn.h>
#include <openssl/bio.h>
#include <string.h>

//BIGNUM *BN_mod_sqrt(BIGNUM *in, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx) 

int main(int argc, char* argv[])
{
    BN_CTX *ctx;
    BIGNUM *a, *p, *in, *ret;
    BIO    *out;

    ctx = BN_CTX_new();

    a = BN_new();
    BN_hex2bn(&a,argv[1]); 

    p = BN_new();
    BN_hex2bn(&p,argv[2]);

    out = BIO_new(BIO_s_file());
    BIO_set_fp(out,stdout,BIO_NOCLOSE);

    in = BN_new();
    ret = BN_mod_sqrt(in, a, p, ctx);

    if(ret != NULL){
        BIO_printf(out, "found (0x%s)^2  = 0x%s mod 0x%s\n", BN_bn2hex(in), argv[1], argv[2]);
    }else{
        BIO_printf(out, "not found  (x)^2 = 0x%s mod 0x%s\n", argv[1], argv[2]);
    }

    BN_free(a);
    BN_free(p);
    BN_free(in);
    BIO_free(out);
    return 0;
}
