#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_snprintf        snprintf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_FS_IO)
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pem.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/bignum.h"
#include "mbedtls/pk.h"
#include "mbedtls/gcm.h"
/*#include "mbedtls/pkparse.h"*/

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFLEN 2048

#endif

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

char* get_random(int len){

    int i, k, ret = 1;

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char *buf = mbedtls_calloc(len, sizeof(unsigned char));

    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) "RANDOM_GEN", 10 );

    mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );

    ret = mbedtls_ctr_drbg_random( &ctr_drbg, buf, len );

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return buf;
}


static int write_file( const char *path, unsigned char *buf, size_t n )
{
    FILE *f;

    if( ( f = fopen( path, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( buf, 1, n, f ) != n )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );
    return( 0 );
}

int read_file(const char *path, unsigned char **buf, size_t *n )
{
	FILE *stream;
	char *fbuf;
	size_t fsize = 0;

	stream = fopen(path, "rb");

	fseek(stream, 0L, SEEK_END);
	fsize = ftell(stream);
	fseek(stream, 0L, SEEK_SET);

	fbuf = malloc(fsize+1);

	size_t size=fread(fbuf,1,fsize,stream);
	fbuf[size]=0;

	fclose(stream);

	*n = fsize;
	*buf = fbuf;

	return 0;
}

int aes_gcm_encrypt(unsigned char* key, size_t key_len, unsigned char* iv, size_t iv_len, unsigned char* input, size_t input_len, unsigned char* aad, unsigned char **output, size_t* output_len, unsigned char** tag, size_t tag_len){
    hexdump("aes encrypt: plaintext", input, input_len);
    hexdump("aes encrypt key", key, key_len);
    hexdump("aes encrypt iv", iv, iv_len);
    hexdump("aes encrypt aad", aad, strlen(aad));

    *output_len = input_len;
    *output = mbedtls_calloc(*output_len, sizeof(unsigned char));

    mbedtls_gcm_context aes;
    mbedtls_gcm_init( &aes );
    mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , (const unsigned char*) key, key_len*8);
    mbedtls_gcm_starts(&aes, MBEDTLS_GCM_ENCRYPT, (const unsigned char*)iv, iv_len, (const unsigned char*) aad, strlen(aad));
    mbedtls_gcm_update(&aes,input_len,(const unsigned char*)input, *output);
    mbedtls_gcm_finish(&aes, *tag, tag_len);
    mbedtls_gcm_free( &aes );

    hexdump("aes encrypt: tag", *tag, tag_len);
    hexdump("aes encrypt: cipher", *output, *output_len);

    return 0;
}

int aes_gcm_decrypt(unsigned char* key, size_t key_len, unsigned char* iv, size_t iv_len, unsigned char* input, size_t input_len, unsigned char* aad, unsigned char** output, size_t* output_len, unsigned char* tag, size_t tag_len){
    hexdump("aes decrypt: cipher", input, input_len);
    hexdump("aes decrypt key", key, key_len);
    hexdump("aes decrypt iv", iv, iv_len);
    hexdump("aes decrypt aad", aad, strlen(aad));
    hexdump("aes decrypt: tag", tag, tag_len);

    *output_len = input_len;

    mbedtls_gcm_context aes;
    mbedtls_gcm_init( &aes );
    mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , (const unsigned char*) key, key_len * 8);
    mbedtls_gcm_starts(&aes, MBEDTLS_GCM_DECRYPT, (const unsigned char*)iv, iv_len, (const unsigned char*) aad, strlen(aad));
    mbedtls_gcm_update(&aes,input_len,(const unsigned char*)input, *output);
    mbedtls_gcm_finish(&aes, tag, tag_len);
    mbedtls_gcm_free( &aes );

    hexdump("aes decrypt: plaintext", *output, *output_len);

    return 0;
}

int hexstring_to_char(const char* hexstr, unsigned char **b_char, size_t *b_len)
{
    size_t len = strlen(hexstr);
    size_t blen = len / 2;
    unsigned char* bins = (unsigned char*)malloc((blen+1) * sizeof(*bins));
    for (size_t i=0, j=0; j<blen; i+=2, j++)
        bins[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    bins[blen] = '\0';

    *b_len = blen;
    *b_char = bins;
    return 0;
}


void main( int argc, char *argv[] )
{

    size_t k_len;
    unsigned 	char *k;
    hexstring_to_char(argv[1], &k, &k_len);

    size_t iv_len;
    unsigned 	char *iv;
    hexstring_to_char(argv[2], &iv, &iv_len);

	/*unsigned     char aad[] = "somedevice.context";*/
    unsigned char *aad = argv[3];

    unsigned char *cipher_info;
    size_t cipher_info_len;
    read_file(argv[4], &cipher_info, &cipher_info_len);

    unsigned char *tag;
    size_t tag_len;
    read_file(argv[5], &tag, &tag_len);

    unsigned char *plaintext =  mbedtls_calloc(cipher_info_len, sizeof(unsigned char));
    size_t plaintext_len;
    aes_gcm_decrypt(k, k_len, iv, iv_len, cipher_info, cipher_info_len, aad, &plaintext, &plaintext_len, tag, tag_len);
    write_file(argv[6], plaintext, plaintext_len);
}
