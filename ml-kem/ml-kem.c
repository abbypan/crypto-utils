#include <stdio.h>
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

	OQS_init();


	const char *alg_name = argv[1];


	if (!OQS_KEM_alg_is_enabled(alg_name)) {
		printf("Algorithm %s is not enabled!\n", alg_name);
		OQS_destroy();
		return EXIT_FAILURE;
	}

	OQS_KEM *kem = OQS_KEM_new(alg_name);
	if (kem == NULL) {
		printf("Failed to create KEM object for %s\n", alg_name);
		OQS_destroy();
		return EXIT_FAILURE;
	}

	uint8_t *public_key = malloc(kem->length_public_key);
	uint8_t *secret_key = malloc(kem->length_secret_key);

	if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
		printf("Failed to generate keypair\n");
		OQS_KEM_free(kem);
		free(public_key);
		free(secret_key);
		OQS_destroy();
		return EXIT_FAILURE;
	}

	hexdump("pub key", public_key, kem->length_public_key);
	hexdump("secret key", secret_key, kem->length_secret_key);

	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret_e = NULL;
	uint8_t *shared_secret_d = NULL;
	OQS_STATUS rc;

	ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
	shared_secret_e = OQS_MEM_malloc(kem->length_shared_secret);
	shared_secret_d = OQS_MEM_malloc(kem->length_shared_secret);

	rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
	hexdump("shared_secret_e", shared_secret_e, kem->length_shared_secret);
	hexdump("ciphertext", ciphertext, kem->length_ciphertext);

	rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
	hexdump("shared_secret_d", shared_secret_d, kem->length_shared_secret);

	OQS_KEM_free(kem);
	free(public_key);
	free(secret_key);
	free(shared_secret_e);
	free(shared_secret_d);
	free(ciphertext);
	OQS_destroy();

	return EXIT_SUCCESS;
}
