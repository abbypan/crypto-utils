# openssl 

## ciphers

openssl ciphers

openssl s_client -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -connect www.google.com:443


## tls

openssl s_client -connect www.taobao.com:443

openssl s_client -connect www.baidu.com -status -msg -CAfile ca-root.pem -untrusted ca-server.pem 
 
openssl verify -verbose -x509_strict -CAfile ca-root.pem -untrusted ca-server.pem tls_server.pem


## cert

生成RSA4096的PKCS#10 格式CSR文件 test.csr，私钥为 test.key

openssl req -nodes -newkey rsa:4096 -keyout test.key -out test.csr -subj "/C=CN/ST=Anhui/L=Hefei/O=USTC/OU=Cybersecurity/CN=PB02210"

openssl req -noout -text -in test.csr

生成自签名证书

openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout CA.key -out CA.crt  -subj "/C=CN/ST=Anhui/L=Hefei/O=USTC/OU=West/CN=Information Science and Technology"

openssl x509 -in CA.crt -text -noout

用CA.key为test.csr签名

openssl req -verify -in test.csr -text -noout

openssl x509 -req -days 360 -in test.csr -CA CA.crt -CAkey CA.key -CAcreateserial -out test.crt -sha256

openssl x509 -text -noout -in test.crt

PEM/DER证书转换

openssl x509 -outform der -in test.crt -out test.der

openssl x509 -inform der -in test.der -out test.pem

PKCS #7文件转换

openssl crl2pkcs7 -nocrl -certfile test.crt -out test.p7b -certfile CA.crt

openssl pkcs7 -print_certs -in test.p7b -out test_with_trust_chain.cer

outform: PEM(default), DER

openssl crl2pkcs7 -nocrl -certfile test.crt -out test.p7c -outform DER -certfile CA.crt

## csr

openssl req -new -key ecc_priv.pem -out ecc.csr -sha256 -subj "/C=CN/ST=Anhui/L=Hefei/O=USTC/OU=Cybersecurity/CN=Infosec"
openssl req -verify -in ecc.csr -text -noout

openssl req -config ee_ext.cnf -new -key ecc_priv.pem -out ecc_ee_ext.csr

openssl req -verify -in ecc_ee_ext.csr -text -noout

openssl x509 -req -days 360 -in ecc_ee_ext.csr -CA CA.crt -CAkey CA.key -CAcreateserial -out ecc_ee_ext.crt -sha256 -extfile ee_ext.cnf -extensions req_ext

openssl x509 -text -in ecc_ee_ext.crt

openssl x509 -in ecc_ee_ext.crt -noout -ext subjectAltName

openssl x509 -in ecc_ee_ext.crt -noout -issuer



## p7s

openssl cms -cmsout -in test.p7s -inform DER -noout -print

## pkcs12

openssl pkcs12 -export -out test.pfx -inkey test.key -in test.crt -certfile CA.crt -password pass:sometestpw

openssl pkcs12 -in test.pfx -out test_all.cer -nodes -password pass:sometestpw

openssl pkcs12 -in test.pfx -out test_only_priv.cer -nodes -nocerts -password pass:sometestpw

openssl pkcs12 -in test.pfx -out test_only_cert.cer -nodes -nokeys -password pass:sometestpw

openssl ecparam -genkey -name prime256v1 -noout -out ecc_priv.pem

## pkcs8

https://www.openssl.org/docs/manmaster/man1/openssl-pkcs8.html

openssl pkcs8 -outform DER -in ecc_priv.der -nocrypt -topk8 -out ecc_priv_pk8.der

## ecc 

openssl ecparam -list_curves

openssl ec -in ecc_priv.pem -pubout -out ecc_pub.pem

openssl ec -pubin -in ecc_pub.pem -conv_form compressed -outform DER -out ecc_pub_compressed.der

openssl ec -pubin -in ecc_pub.pem -outform DER -conv_form uncompressed -pubout -out ecc_pub_uncompressed.der



# signature 

openssl dgst -sha256 -sign ecc_priv.pem -out src.ecc.sig src.txt

openssl dgst -sha256 -verify ecc_pub.pem -signature src.ecc.sig src.txt

注意，如果手动生成hash再调用私钥进行签名，使用pkeyutl，而非rsautl。否则生成的签名文件可能与直接调dgst -sign生成的签名文件不同：https://stackoverflow.com/questions/9380856/different-signatures-when-using-c-routines-and-openssl-dgst-rsautl-commands

openssl genrsa -out rsa_priv.pem 4096

openssl rsa -in rsa_priv.pem -pubout > rsa_pub.pem


openssl dgst -sha256 -binary -sign rsa_priv.pem -out src.txt.rsa.sig src.txt

openssl dgst -sha256 -verify rsa_pub.pem -signature src.txt.rsa.sig src.txt


openssl dgst -sha256 -binary src.txt > src.txt.sha256

openssl pkeyutl -sign -in src.txt.sha256 -inkey rsa_priv.pem -pkeyopt digest:sha256 -out src.txt.sha256.rsa.sig

openssl dgst -sha256 -verify rsa_pub.pem -signature src.txt.sha256.rsa.sig src.txt


openssl pkeyutl -sign -in src.txt.sha256 -inkey rsa_priv.pem -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256 -out src.txt.sha256.rsa.pss.sig

openssl pkeyutl -verify -pubin -inkey rsa_pub.pem -sigfile src.txt.sha256.rsa.pss.sig -in src.txt.sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha256


## Curve25519

openssl genpkey -algorithm X25519 -out test25519_priv.pem

openssl pkey -in test25519_priv.pem -pubout -out test25519_pub.pem


openssl genpkey -algorithm ed25519  -out ed25519_priv.pem

openssl genpkey -algorithm x25519  -out x25519_priv.pem


ssh-keygen -t ed25519 -o -a 256

 https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_derive.html
 https://github.com/alexkrontiris/OpenSSL-x25519-key_exchange
 https://www.openssl.org/docs/manmaster/man7/X25519.html
 https://www.openssl.org/docs/manmaster/man7/Ed25519.html

## aes

openssl enc -aes-256-cbc -salt -in src.txt -out src.aes-256-cbc.enc -k somepasswd ; wc src.txt src.aes-256-cbc.enc

openssl enc -aes-256-ctr -k somepasswd -in src.txt -out src.aes-256-ctr.enc ; wc src.txt src.aes-256-ctr.enc

openssl enc -aes-128-ctr -in src.txt -out src.aes-128-ctr.enc -K a6a7ee7abe681c9c4cede8e3366a9ded -iv 87b7225d16ea2ae1f41d0b13fdce9bba

openssl enc -d -aes-128-ctr -in src.aes-128-ctr.enc -out src.txt.dec -K a6a7ee7abe681c9c4cede8e3366a9ded -iv 87b7225d16ea2ae1f41d0b13fdce9bba


gcc -Wall -lcrypto -o aes256gcm aes256gcm.c

gcc -Wall -lcrypto -o aes256gcm-decrypt aes256gcm-decrypt.c

KEY=a6a7ee7abe681c9c4cede8e3366a9ded96b92668ea5e26a31a4b0856341ed224

IV=87b7225d16ea2ae1f41d0b13fdce9bba


echo -n 'plain text' | ./aes256gcm $KEY $IV | od -t x1

cat src.txt | ./aes256gcm $KEY $IV > src.aes-256-gcm.enc

cat src.aes-256-gcm.enc | ./aes256gcm-decrypt $KEY $IV


## hmac

openssl mac -macopt digest:SHA256 -macopt hexkey:a27e195cf3ea9755eceb1f77ca0dd20ba1fdaa8832f1b2fb637c8912ad3dce13 -in plain.txt HMAC

## sm

openssl ecparam -genkey -name SM2 -out sm2_priv.pem

openssl req -new -key sm2_priv.pem -out sm2.csr -sm3 -pkeyopt "sm2_id:123456786666" -subj "/C=CN/ST=Anhui/L=Hefei/O=USTC/OU=Cybersecurity/CN=PB02210"

openssl x509 -req -in sm2.csr -signkey sm2_priv.pem -out sm2.crt -sm3

openssl x509 -in sm2.crt -text -noout


openssl ecparam -genkey -name SM2 -out sm2_root_priv.pem

openssl req -new -nodes -key sm2_root_priv.pem -out sm2_root.csr -sm3 -pkeyopt "sm2_id:123456789999" -subj "/C=CN/ST=Anhui/L=Hefei/O=USTC/OU=West/CN=Information Science and Technology"

openssl x509 -req -in sm2_root.csr -signkey sm2_root_priv.pem -out sm2_root.crt -sm3 -extfile root_ext.cnf

openssl x509 -in sm2_root.crt -text -noout


openssl ecparam -genkey -name SM2 -noout -out sm2_ee_priv.pem

openssl pkey -in sm2_ee_priv.pem -pubout -out sm2_ee_pub.pem

openssl req -new -sm3 -nodes -out sm2_ee.csr -key sm2_ee_priv.pem -config ee.cnf

openssl req -verify -in sm2_ee.csr -text -noout

openssl x509 -req -in sm2_ee.csr -CA sm2_root.crt -CAkey sm2_root_priv.pem -CAcreateserial -out sm2_ee_cert.pem -days 1111 -sm3 -extfile ee_ext.cnf

openssl x509 -text -in sm2_ee_cert.pem

