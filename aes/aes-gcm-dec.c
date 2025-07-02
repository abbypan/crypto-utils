#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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

int aes_gcm_dec_file(
		unsigned char *key,  
		size_t key_len, 

		//unsigned char *iv, 
		size_t iv_len, 

		size_t tag_len, 

		unsigned char *aad, size_t aad_len, 

		char *input_file,  char *output_file
		) {

	EVP_CIPHER_CTX *ctx = NULL;
	FILE *in = NULL, *out = NULL;
	unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int inlen, outlen;
	unsigned char tag[16];
	unsigned char iv[16];
	int ret = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) goto err;
	if (!(in = fopen(input_file, "rb"))) goto err;
	if (!(out = fopen(output_file, "wb"))) goto err;

	fseek(in, 0, SEEK_END);
	int file_size = ftell(in);

	fseek(in, 0, SEEK_SET);
	if (fread(iv, 1, iv_len, in) != iv_len) goto err;
	hexdump("iv", iv, iv_len);

	fseek(in, -tag_len, SEEK_END);
	if (fread(tag, 1, tag_len, in) != tag_len) goto err;
	hexdump("tag", tag, tag_len);

	fseek(in, iv_len, SEEK_SET);

	int processed = iv_len;
	file_size -= tag_len;

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto err;
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;

	if(1 != EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len))
		goto err;

	while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
		processed+=inlen;
		if(file_size<processed){
			inlen -= (processed - file_size);
		}
		if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) goto err;
		if (fwrite(outbuf, 1, outlen, out) != outlen) goto err;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) goto err;
	if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) goto err;
	if (fwrite(outbuf, 1, outlen, out) != outlen) goto err;

	ret = 1;
err:
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	if (in) fclose(in);
	if (out) fclose(out);
	return ret;
}

int main(int argc, char *argv[]) {


	size_t key_len;
	unsigned char* key = OPENSSL_hexstr2buf(argv[1], &key_len);

	size_t iv_len =12;
	//unsigned char* iv = OPENSSL_hexstr2buf(argv[2], &12);

	int tag_len =16;

	unsigned char* aad = argv[2];
	size_t aad_len = strlen(argv[2]);

	unsigned char* cipher_f = argv[3];
	unsigned char* dec_f = argv[4];

	hexdump("k", key, key_len);


	if(!aes_gcm_dec_file(key, key_len, iv_len, tag_len, aad, aad_len, cipher_f, dec_f)) {
		fprintf(stderr, "decrypt fail: %s, aad %s\n", cipher_f, aad);
		return 1;
	}

	printf("decrypt success: %s -> %s\n", cipher_f, dec_f);
	return 0;
}
