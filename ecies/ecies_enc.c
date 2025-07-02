#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>

#define BUFLEN 2048

int gen_random(unsigned char **r, int len) {

	*r = OPENSSL_malloc(len);
	if (RAND_bytes(*r, len) != 1) {
		OPENSSL_free(*r);
		return 0;
	}

	return len;
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

EVP_PKEY* do_ec_keygen(int nid)
{

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

void write_private_key(char* fname, EVP_PKEY* pkey){
    BIO *privout;
    privout = BIO_new_file(fname, "w+");
    PEM_write_bio_PrivateKey(privout, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_flush(privout);
}

void write_public_key(char* fname, EVP_PKEY* pkey){
    BIO *pubout;
    pubout = BIO_new_file(fname, "w+");
    PEM_write_bio_PUBKEY(pubout, pkey);
    BIO_flush(pubout);
}

int hkdf(
                 unsigned char *ikm, size_t ikm_len,
		 unsigned char *salt, size_t salt_len,
                 unsigned char *info, size_t info_len,
                unsigned char **out, size_t out_len) {
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

    hexdump("ikm", ikm, ikm_len);
    hexdump("salt", salt, salt_len);
    hexdump("info", info, info_len);

    *out = OPENSSL_malloc(out_len);
    if (EVP_PKEY_derive(pctx, *out, &out_len) <= 0) {
	    OPENSSL_free(*out);
        goto err;
    }

    hexdump("out", *out, out_len);

    ret = 1;

err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
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

int main(int argc, char *argv[]) {
    // temp_priv_key, peer_pub_key, Z = ecdh
    // k = hkdf(Z)
    // cipher = aes(k, data)
   
    FILE *peer_pubkeyfile = fopen(argv[1], "r");
    EVP_PKEY *peer_pubkey = NULL;
    peer_pubkey = PEM_read_PUBKEY(peer_pubkeyfile, NULL, NULL, NULL);
    printf("\nRead Peer Ephemeral PUBKEY Key:\n");
    PEM_write_PUBKEY(stdout, peer_pubkey);

    EVP_PKEY *pkey = do_ec_keygen(NID_X9_62_prime256v1);
    unsigned char *publicKey = NULL;
    size_t publicLen = 0;
    publicLen = i2d_PUBKEY(pkey, &publicKey);

    EVP_PKEY *pubKey = NULL;
    pubKey = d2i_PUBKEY(&pubKey, (const unsigned char **) &publicKey, publicLen);
    PEM_write_PUBKEY(stdout, pubKey);
    write_public_key(argv[2], pubKey);

    unsigned char* plain_f = argv[3];
    unsigned char* cipher_f = argv[4];


    EVP_PKEY_CTX *ctx;
    unsigned char *z;
    size_t zlen;
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pubkey);
    EVP_PKEY_derive(ctx, NULL, &zlen);

    z = OPENSSL_malloc(zlen);
    EVP_PKEY_derive(ctx, z, &zlen);
    hexdump("Z", z, zlen);

    unsigned char *k= NULL;
    int k_len = 32;

    unsigned char *digest_name = "SHA256";
    unsigned char salt[] = { 0x00 };
    int salt_len = sizeof(salt)/sizeof(salt[0]);
    unsigned char info[] = "";
    int info_len = sizeof(info)/sizeof(info[0]);

    hkdf( z, zlen, salt, salt_len, info, info_len, &k,  k_len );
    hexdump("k", k, k_len);

    unsigned char aad[] = "";
    int aad_len = sizeof(aad)/sizeof(aad[0]);

    int iv_len = 12;
    unsigned char *iv;
    gen_random(&iv, iv_len);

    int tag_len = 16;

	if(!aes_gcm_enc_file(k, k_len, iv, iv_len, aad, aad_len, plain_f, cipher_f)) {
		fprintf(stderr, "encrypt fail: %s, aad %s\n", plain_f, aad);
		return 1;
	}

	printf("encrypt success: %s -> %s\n", plain_f, cipher_f);
    return 0;
}
