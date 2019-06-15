#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/aes.h> 
#include <openssl/asn1.h> 
#include <openssl/bio.h> 
#include <openssl/crypto.h>
#include <openssl/evp.h> 
#include <openssl/ec.h> 
#include <openssl/hmac.h>
#include <openssl/pem.h> 
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h> 

#define OUR_CIPHER_NAME "aes-256-cbc"
#define OUR_PBKDF2_MD "sha256"
#define OUR_MACDATA_MD "sha256"

int pbe2_cipher_decrypt(const EVP_CIPHER *cipher, unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
		unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		return;

	if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
		return;

	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		return;
	plaintext_len = len;

	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		return;
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void write_binary_f(unsigned char *fname, unsigned char *x , unsigned int len) 
{
	FILE * hfp;
	hfp = fopen (fname, "wb");
	fwrite( x,sizeof(unsigned char), len, hfp);
	fclose(hfp);
}

void write_octet_f(unsigned char *fname, ASN1_OCTET_STRING *os){
	unsigned char *os_str = ASN1_STRING_data(os);
	long os_len = ASN1_STRING_length(os);
	write_binary_f(fname, os_str, os_len);
}

int verify_macdata(PKCS12 *p12, const char *pass, int passlen)
{
	ASN1_OCTET_STRING *salt = p12->mac->salt;
	write_octet_f("mac_salt.bin", salt);

	int iter = ASN1_INTEGER_get(p12->mac->iter);

	const EVP_MD *md_type = EVP_get_digestbyname(OUR_MACDATA_MD);
	int md_size = EVP_MD_size(md_type);

	//generate mac key
	unsigned char key[EVP_MAX_MD_SIZE];
	PKCS12_key_gen (pass, passlen, salt->data, salt->length, PKCS12_MAC_ID, iter,
			md_size, key, md_type);
	write_binary_f("mac_key.bin", key, md_size);

	//read authsafes data
	ASN1_OCTET_STRING *authsafes_d = p12->authsafes->d.data;
	write_octet_f("mac_authsafes_d_data.bin", authsafes_d);

	//calc mac digest
	HMAC_CTX hmac;
	unsigned char calc_mac[EVP_MAX_MD_SIZE];
	unsigned int calc_mac_len;

	HMAC_CTX_init(&hmac);
	if (!HMAC_Init_ex(&hmac, key, md_size, md_type, NULL)
			|| !HMAC_Update(&hmac, authsafes_d->data, authsafes_d->length)
			|| !HMAC_Final(&hmac, calc_mac, &calc_mac_len))
	{
		HMAC_CTX_cleanup(&hmac);


		return 0;
	}
	HMAC_CTX_cleanup(&hmac);
	write_binary_f("mac_calculate_digest_data.bin", calc_mac, calc_mac_len);

	//read mac digest
	ASN1_OCTET_STRING *mac_octet = p12->mac->dinfo->digest;
	write_octet_f("mac_digest_data.bin", mac_octet);

	if ((calc_mac_len != (unsigned int) mac_octet->length)
			|| memcmp (calc_mac, mac_octet->data, calc_mac_len)) return 0;
	return 1;
}

void pbe2_pbkdf2_key_iv(X509_ALGOR *alg, const char* password, int passlen, 
		unsigned char *key, int keylen, unsigned char *iv){

	int aparamtype;
	ASN1_OBJECT *aoid;
	void *aparam;
	X509_ALGOR_get0(&aoid, &aparamtype, &aparam, alg);
	PBE2PARAM *pbe2 = pbe2 = ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBE2PARAM));

	X509_ALGOR_get0(&aoid, &aparamtype, &aparam, pbe2->keyfunc);
	PBKDF2PARAM *kdf =  ASN1_item_unpack(aparam, ASN1_ITEM_rptr(PBKDF2PARAM));

	ASN1_OCTET_STRING *salt = kdf->salt->value.octet_string;
	//write_octet_f("ttt_salt.bin", salt);

	int iter = ASN1_INTEGER_get(kdf->iter);
	//printf("iter: %d\n", iter);

	ASN1_OCTET_STRING *iv_octet = pbe2->encryption->parameter->value.octet_string;
	//write_octet_f("ttt_iv.bin", iv_octet);
	memcpy(iv, iv_octet->data, iv_octet->length);

	const EVP_MD *md_type = EVP_get_digestbyname(OUR_PBKDF2_MD);
	PKCS5_PBKDF2_HMAC(password, passlen, salt->data, salt->length, iter, md_type, keylen, key);
	//write_binary_f("ttt_key.bin", *key, *keylen);
}

unsigned char* pbe2_decrypt(ASN1_OCTET_STRING *enc_data, X509_ALGOR *alg, const char* password, int passlen, int *plaintext_len){
	const EVP_CIPHER *cipher = EVP_get_cipherbyname(OUR_CIPHER_NAME);

	int key_len = EVP_CIPHER_key_length(cipher);
	unsigned char *key = malloc(key_len); 
	int iv_len = EVP_CIPHER_iv_length(cipher);
	unsigned char *iv = malloc(iv_len); 

	pbe2_pbkdf2_key_iv(alg, password, passlen, key, key_len, iv);
	unsigned char* plaintext = malloc(enc_data->length);

	*plaintext_len=pbe2_cipher_decrypt(cipher, enc_data->data, enc_data->length, key, iv, plaintext); 
	//printf("plaintext len %d\n", *plaintext_len);

	free(key);
	free(iv);

	return plaintext; 
}

X509* decrypt_cert(PKCS7 *p7, const char* password, int passlen){
	ASN1_OCTET_STRING *enc_data = p7->d.encrypted->enc_data->enc_data;
	write_octet_f("cert_enc.bin", enc_data);

	X509_ALGOR *alg = p7->d.encrypted->enc_data->algorithm;

	int plaintext_len;
	unsigned char* plaintext = pbe2_decrypt(enc_data, alg, password, passlen, &plaintext_len);
	write_binary_f("cert_plain.bin", plaintext, plaintext_len);

	void *bags = ASN1_item_d2i(NULL, (const unsigned char **) &plaintext, plaintext_len, ASN1_ITEM_rptr(PKCS12_SAFEBAGS));
	PKCS12_SAFEBAG *cert_bag = sk_PKCS12_SAFEBAG_value(bags, 0);
	ASN1_OCTET_STRING *cert_d = cert_bag->value.bag->value.octet;
	write_octet_f("cert_final.bin", cert_d);

	X509 *x509;
	x509 = ASN1_item_unpack(cert_d, ASN1_ITEM_rptr(X509));

	return x509;
}

EC_KEY* decrypt_priv(PKCS7 *p7, const char* password, int passlen){

	STACK_OF(PKCS12_SAFEBAG) *bags= PKCS12_unpack_p7data(p7);
	PKCS12_SAFEBAG *bag= sk_PKCS12_SAFEBAG_value(bags, 0);
	const X509_SIG *p8 = bag->value.shkeybag;

	ASN1_OCTET_STRING *enc_data = p8->digest;
	write_octet_f("priv_enc.bin", enc_data);

	X509_ALGOR *alg = p8->algor;

	int plaintext_len;
	unsigned char* plaintext = pbe2_decrypt(enc_data, alg, password, passlen, &plaintext_len);
	write_binary_f("priv_plain.bin", plaintext, plaintext_len);

	PKCS8_PRIV_KEY_INFO *p8inf;
	p8inf = (PKCS8_PRIV_KEY_INFO *) ASN1_item_d2i(NULL, (const unsigned char **) &plaintext, plaintext_len, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO));
	write_octet_f("priv_final.bin", p8inf->pkey->value.octet_string);

	EVP_PKEY *p8key = EVP_PKCS82PKEY(p8inf);
	EC_KEY* pkey_ec = EVP_PKEY_get1_EC_KEY(p8key);

	return pkey_ec;
}


int main(int argc, char *argv[])
{
	// Load the pfx file.
	PKCS12 *p12;
	FILE *fp = fopen(argv[1], "rb");
	if( fp == NULL ) { perror("fopen"); return 1; }
	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);

	OpenSSL_add_all_algorithms();
	ERR_load_PKCS12_strings();
	if( p12 == NULL ) { ERR_print_errors_fp(stderr); exit(1); }

	//password
	const char *password = argv[2];
	int passlen = strlen(password);


	//verify mac
	int mac_verify_result = verify_macdata(p12, password, passlen);
	printf("verify mac:%d\n", mac_verify_result);

	//read authsafes data
	STACK_OF(PKCS7) *asafes;
	STACK_OF(PKCS12_SAFEBAG) *bags;
	int i, bagnid;
	PKCS7 *p7;
	asafes = PKCS12_unpack_authsafes(p12);
	PKCS12_SAFEBAG *bag;

	//decrypt cert
	PKCS7 *cert_p7 = sk_PKCS7_value(asafes, 0);
	X509 *x509= decrypt_cert(cert_p7, password, passlen);
	BIO *out;
	out = BIO_new_file ("cert_final.pem", "w");
	PEM_write_bio_X509(out, x509);

	//decrypt private key
	PKCS7 *priv_p7 = sk_PKCS7_value(asafes, 1);
	EC_KEY *pkey_ec= decrypt_priv(priv_p7, password, passlen); 
	BIO* pr_out = BIO_new_file ("priv_final.pem", "w");
	PEM_write_bio_ECPrivateKey(pr_out, pkey_ec, NULL, NULL, 0, NULL, NULL);

	return 0;
}
