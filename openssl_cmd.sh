#!/bin/bash

#连接在线证书，列出trust chain
#openssl s_client -connect www.taobao.com:443

#生成RSA4096的PKCS#10 格式CSR文件 test.csr，私钥为 test.key
openssl req -nodes -newkey rsa:4096 -keyout test.key -out test.csr -subj "/C=CN/ST=Anhui/L=Hefei/O=USTC/OU=Cybersecurity/CN=PB02210"
openssl req -noout -text -in test.csr

#生成自签名证书
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout CA.key -out CA.crt  -subj "/C=CN/ST=Anhui/L=Hefei/O=USTC/OU=West/CN=Information Science and Technology"
openssl x509 -in CA.crt -text -noout

#用CA.key为test.csr签名
openssl req -verify -in test.csr -text -noout
openssl x509 -req -days 360 -in test.csr -CA CA.crt -CAkey CA.key -CAcreateserial -out test.crt -sha256
openssl x509 -text -noout -in test.crt

#PEM/DER证书转换
openssl x509 -outform der -in test.crt -out test.der
openssl x509 -inform der -in test.der -out test.pem

#PKCS #7文件转换
openssl crl2pkcs7 -nocrl -certfile test.crt -out test.p7b -certfile CA.crt
openssl pkcs7 -print_certs -in test.p7b -out test_with_trust_chain.cer

#outform: PEM(default), DER
openssl crl2pkcs7 -nocrl -certfile test.crt -out test.p7c -outform DER -certfile CA.crt

#PKCS #12文件转换
openssl pkcs12 -export -out test.pfx -inkey test.key -in test.crt -certfile CA.crt -password pass:sometestpw
openssl pkcs12 -in test.pfx -out test_all.cer -nodes -password pass:sometestpw
openssl pkcs12 -in test.pfx -out test_only_priv.cer -nodes -nocerts -password pass:sometestpw
openssl pkcs12 -in test.pfx -out test_only_cert.cer -nodes -nokeys -password pass:sometestpw

#ECC curves
openssl ecparam -list_curves

#ecc generate private key & public key
openssl ecparam -genkey -name prime256v1 -noout -out ecc_priv.pem
openssl ec -in ecc_priv.pem -pubout -out ecc_pub.pem

#ecc csr
openssl req -new -key ecc_priv.pem -out ecc.csr -sha256 -subj "/C=CN/ST=Anhui/L=Hefei/O=USTC/OU=Cybersecurity/CN=Infosec"
openssl req -verify -in ecc.csr -text -noout

#ecc sign & verify
openssl dgst -sha256 -sign ecc_priv.pem -out src.sign src.txt
openssl dgst -sha256 -verify ecc_pub.pem -signature src.sign src.txt
