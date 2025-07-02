#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hkdf_derive(const unsigned char *salt, size_t salt_len,
                const unsigned char *ikm, size_t ikm_len,
                const unsigned char *info, size_t info_len,
                unsigned char *out, size_t out_len) {
    EVP_PKEY_CTX *pctx;
    int ret = 0;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        return 0;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto err;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
        goto err;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) <= 0) {
        goto err;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
        goto err;
    }

    if (EVP_PKEY_derive(pctx, out, &out_len) <= 0) {
        goto err;
    }

    ret = 1;

err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int main() {
    unsigned char ikm[] = "input key material";
    unsigned char salt[] = "salt";
    unsigned char info[] = "hkdf example";
    unsigned char out[32];  

    if (!hkdf_derive(salt, strlen((char *)salt),
                     ikm, strlen((char *)ikm),
                     info, strlen((char *)info),
                     out, sizeof(out))) {
        fprintf(stderr, "hkdf fail\n");
        return 1;
    }

    for (size_t i = 0; i < sizeof(out); i++) {
        printf("%02x", out[i]);
    }
    printf("\n");

    return 0;
}
