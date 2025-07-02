#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int gen_random(unsigned char **r, int len) {

	*r = OPENSSL_malloc(len);
	if (RAND_bytes(*r, len) != 1) {
		OPENSSL_free(*r);
		return 0;
	}

	return len;
}

int aes_gcm_enc_file(
		 unsigned char *key, size_t key_len, 
		 unsigned char *iv, size_t iv_len, 
		 unsigned char *aad, size_t aad_len, 
		 char *input_file, const char *output_file
                ) {
    FILE *in_file = NULL, *out_file = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    unsigned char tag[16];
    int tag_len = 16;

    if(!(ctx = EVP_CIPHER_CTX_new())) goto err;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) goto err;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;

    if(1 != EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len))
        goto err;

    if(!(in_file = fopen(input_file, "rb"))) {
        perror("Input file open error");
        return 0;
    }

    if(!(out_file = fopen(output_file, "wb"))) {
        perror("Output file open error");
        fclose(in_file);
        return 0;
    }

    if(fwrite(iv, 1, 12, out_file) != 12) {
        perror("IV write error");
        fclose(in_file);
        fclose(out_file);
        return 0;
    }

    while((inlen = fread(inbuf, 1, sizeof(inbuf), in_file)) > 0) {
        if(1 != EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen))
            goto err;
        if(fwrite(outbuf, 1, outlen, out_file) != outlen) {
            perror("Data write error");
            fclose(in_file);
            fclose(out_file);
            return 0;
        }
    }

    if(1 != EVP_EncryptFinal_ex(ctx, outbuf, &outlen))
        goto err;
    if(outlen > 0) {
        if(fwrite(outbuf, 1, outlen, out_file) != outlen) {
            perror("Final data write error");
            fclose(in_file);
            fclose(out_file);
            return 0;
        }
    }

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
        goto err;

    if(fwrite(tag, 1, tag_len, out_file) != tag_len) {
        perror("Tag write error");
        fclose(in_file);
        fclose(out_file);
        return 0;
    }

err:
    fclose(in_file);
    fclose(out_file);
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

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


	size_t key_len;
	unsigned char* key = OPENSSL_hexstr2buf(argv[1], &key_len);

	size_t iv_len;
	unsigned char* iv = OPENSSL_hexstr2buf(argv[2], &iv_len);

	unsigned char* aad = argv[3];
	size_t aad_len = strlen(argv[3]);
	printf("aad: %s\n", aad);

	unsigned char* plain_f = argv[4];
	unsigned char* cipher_f = argv[5];


	if(!aes_gcm_enc_file(key, key_len, iv, iv_len, aad, aad_len, plain_f, cipher_f)) {
		fprintf(stderr, "encrypt fail: %s\n", plain_f);
		return 1;
	}

	printf("encrypt success: %s -> %s\n", plain_f, cipher_f);
	return 0;
}
