#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

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

    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_e = NULL;
    uint8_t *shared_secret_d = NULL;

    //const char *alg_name = OQS_KEM_alg_bike_l1;
    const char *alg_name = argv[1];

    if (!OQS_KEM_alg_is_enabled(alg_name)) {
        printf("Algorithm %s is not enabled!\n", alg_name);
        return EXIT_FAILURE;
    }

    kem = OQS_KEM_new(alg_name);
    if (kem == NULL) {
        fprintf(stderr, "Failed to initialize KEM %s\n", alg_name);
        return EXIT_FAILURE;
    }

    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    ciphertext = malloc(kem->length_ciphertext);
    shared_secret_e = malloc(kem->length_shared_secret);
    shared_secret_d = malloc(kem->length_shared_secret);

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Keypair generation failed\n");
        goto cleanup;
    }

    hexdump("public_key", public_key, kem->length_public_key);
    hexdump("secret_key", secret_key, kem->length_secret_key);

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Encapsulation failed\n");
        goto cleanup;
    }

    hexdump("ciphertext", ciphertext, kem->length_ciphertext);
    hexdump("shared_secret_e", shared_secret_e, kem->length_shared_secret);


    if (OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Decapsulation failed\n");
        goto cleanup;
    }

    hexdump("shared_secret_d", shared_secret_d, kem->length_shared_secret);

cleanup:
    OQS_MEM_secure_free(public_key, kem->length_public_key);
    OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    OQS_MEM_secure_free(ciphertext, kem->length_ciphertext);
    OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
    OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);

    OQS_KEM_free(kem);
    return 0;
}

