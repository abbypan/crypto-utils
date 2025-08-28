#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <pbc/pbc.h>
#include <bswabe.h>

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
	printf("\n\n");

	return;
}


int main() {

	// setup
	bswabe_pub_t* pub = NULL;
	bswabe_msk_t* msk = NULL;
	bswabe_setup(&pub, &msk);


	// keygen	
	bswabe_prv_t* dog_prv = NULL;
	char* dog_attr[] = {"tofu", "dog", NULL};
	dog_prv = bswabe_keygen(pub, msk, (char **) dog_attr);

	bswabe_prv_t* cat_prv = NULL;
	char* cat_attr[] = {"tofu", "cat", NULL};
	cat_prv = bswabe_keygen(pub, msk, (char **) cat_attr);


	// encrypt

	//bswabe cp-abe 
	//char* policy_lang = "tofu and dog";
	//char *policy = parse_policy_lang(policy_lang);

	char* policy = "tofu dog 2of2";

	element_t eek; 
	bswabe_cph_t* cph = NULL;
	cph = bswabe_enc(pub, eek, policy);

	GByteArray* cph_buf;
	cph_buf = bswabe_cph_serialize(cph);

	int eek_len = element_length_in_bytes(eek);
	unsigned char *eek_bytes =malloc(eek_len);
	int eek_bytes_len = element_to_bytes(eek_bytes, eek);

	printf("Encryption\n");
	hexdump("cph", cph_buf->data, cph_buf->len);
	element_printf("policy: %s\neek: %B\n\n", policy, eek);


	// decrypt 

	element_t dog_dek;

	if (!bswabe_dec(pub, dog_prv, cph, dog_dek)) {
		fprintf(stderr, "dog Decryption failed\n\n");
	}else{
		printf("dog Decryption successful\n");

		int dek_len = element_length_in_bytes(dog_dek);
		unsigned char *dek_bytes =malloc(dek_len);
		int dek_bytes_len = element_to_bytes(dek_bytes, dog_dek);
		element_printf("dog dek: %B\n\n", dog_dek);

		free(dek_bytes);
	}

	element_t cat_dek;

	if (!bswabe_dec(pub, cat_prv, cph, cat_dek)) {
		fprintf(stderr, "cat Decryption failed\n\n");
	}else{
		printf("cat Decryption successful\n");

		int dek_len = element_length_in_bytes(cat_dek);
		unsigned char *dek_bytes =malloc(dek_len);
		int dek_bytes_len = element_to_bytes(dek_bytes, cat_dek);
		element_printf("cat dek: %B\n\n", cat_dek);

		free(dek_bytes);
	}




err:
	bswabe_msk_free(msk);
	bswabe_cph_free(cph);
	//bswabe_pub_free(pub);
	//bswabe_prv_free(prv);
	free(eek_bytes);
	//free(dek_bytes);

	return 0;
}
