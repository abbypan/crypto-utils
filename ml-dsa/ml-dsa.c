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
	OQS_init();

	const char *alg_name = argv[1];

	if (!OQS_SIG_alg_is_enabled(alg_name)) {
		printf("Algorithm %s is not enabled!\n", alg_name);
		OQS_destroy();
		return EXIT_FAILURE;
	}

	OQS_SIG *sig = OQS_SIG_new(alg_name);
	if (sig == NULL) {
		printf("Failed to create SIG object for %s\n", alg_name);
		OQS_destroy();
		return EXIT_FAILURE;
	}

	uint8_t *public_key = malloc(sig->length_public_key);
	uint8_t *secret_key = malloc(sig->length_secret_key);


	uint8_t *message = (uint8_t *)"msg for test";
	size_t message_len = strlen((char *)message);

	hexdump("message", message, message_len);

	uint8_t *signature = malloc(sig->length_signature);
	size_t signature_len;


	if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
		printf("Failed to generate keypair\n");
		goto cleanup;
	}

	hexdump("public_key", public_key, sig->length_public_key);
	hexdump("secret_key", secret_key, sig->length_secret_key);

	if (OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key) != OQS_SUCCESS) {
		printf("Failed to sign message\n");
		goto cleanup;
	}

	hexdump("signature", signature, signature_len);

	if (OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key) != OQS_SUCCESS) {
		printf("Failed to verify signature!\n");
		goto cleanup;
	}
	printf("Successful to verify signature!\n");

cleanup:
	OQS_SIG_free(sig);
	free(public_key);
	free(secret_key);
	free(signature);
	OQS_destroy();

	return EXIT_SUCCESS;
}
