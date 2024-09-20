#!/bin/bash    

#saltlen == EVP_MD_CTX_FLAG_PSS_MDLEN  ~  -1
#saltlen == EVP_MD_CTX_FLAG_PSS_MREC   ~  -2 

# openssl genrsa -out rsa_priv.pem 2048
# openssl rsa -in rsa_priv.pem -pubout -out rsa_pub.pem

# openssl rsa -text -pubin -in rsa_pub.pem
# openssl rsa -noout -modulus -pubin -in rsa_pub.pem

# echo "ababcdcd" | xxd -r -p > src.bin
# openssl dgst -sha256 -binary -out src.dgst src.bin

# openssl pkeyutl -sign -in src.dgst -inkey rsa_priv.pem -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256 -out src.sig
# openssl pkeyutl -verify -pubin -inkey rsa_pub.pem -sigfile src.sig -in src.dgst -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256
# openssl dgst -sha256 -verify rsa_pub.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -signature src.sig src.bin

openssl dgst -sha256 -sign rsa_priv.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -out src.direct.sig src.bin
openssl dgst -sha256 -verify rsa_pub.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -signature src.direct.sig src.bin
