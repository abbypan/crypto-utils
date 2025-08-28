#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

int main(int argc, char **argv) {

	InitializeOpenABE();

	cout << "KP-ABE:" << endl;

	OpenABECryptoContext kpabe("KP-ABE");

	kpabe.generateParams();

	std::string mpk;
	kpabe.exportPublicParams(mpk);
	cout << "mpk: " << mpk << endl;

	std::string msk;
	kpabe.exportSecretParams(msk);
	cout << "msk: " << msk << endl << endl;

	string ct, pt = "some secret data details", dog_pt, cat_pt;

	kpabe.keygen("dog and tofu", "dog");
	std::string dogKey;
	kpabe.exportUserKey("dog", dogKey);
	cout << "dogKey: " << dogKey << endl;

	kpabe.keygen("cat and tofu", "cat");
	std::string catKey;
	kpabe.exportUserKey("cat", catKey);
	cout << "catKey: " << catKey << endl;

	string enc_attr = "|dog|tofu";
	kpabe.encrypt(enc_attr, pt, ct);
	cout << "\nEncryption:\nplaintext: " << pt << "\nenc_attr: " << enc_attr << "\nciphertext: " << ct << endl << endl;

	bool dog_result = kpabe.decrypt("dog", ct, dog_pt);
	if(dog_result && pt == dog_pt){
		cout << "dog Decrypted successful: " << dog_pt << endl << endl;
	}else{
		cout << "dog Decrypted fail" << endl << endl; 
	}


	bool cat_result = kpabe.decrypt("cat", ct, cat_pt);
	if(cat_result && pt == cat_pt){
		cout << "cat Decrypted successful: " << cat_pt << endl << endl;
	}else{
		cout << "cat Decrypted fail" << endl << endl; 
	}

	ShutdownOpenABE();

	return 0;
}
