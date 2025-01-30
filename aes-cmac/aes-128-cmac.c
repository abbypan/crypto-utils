#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/cmac.h>

int main(int argc, char *argv[])
{

    long key_len;
    unsigned char *key = OPENSSL_hexstr2buf(argv[1], &key_len);

    long data_len;
    unsigned char *data = OPENSSL_hexstr2buf(argv[2], &data_len);

    unsigned char mac[16] = {0}; 
    size_t mac_len;

    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);

    CMAC_Update(ctx, data, data_len);
    CMAC_Final(ctx, mac, &mac_len);

    char *mac_hexstr = OPENSSL_buf2hexstr(mac, (long) mac_len);

    printf("key_hexstr: %s\ndata_hexstr: %s\naes-128-cmac_hexstr: %s\n", argv[1], argv[2], mac_hexstr);

    CMAC_CTX_free(ctx);

    OPENSSL_free(key);
    OPENSSL_free(data);
    OPENSSL_free(mac_hexstr);

    return 0;
}
