#!/bin/bash

##server ca {
#openssl ecparam -genkey -name prime256v1 -noout -out server_root_priv.pem
openssl pkcs8 -topk8 -inform pem -in server_root_priv.pem -outform pem -nocrypt -out server_root_priv_pkcs8.pem
#openssl ec -in server_root_priv.pem -pubout -out server_root_pub.pem
#openssl req -new -key server_root_priv.pem -out server_root.csr -sha256 -config server_root.cnf
#openssl req -verify -in server_root.csr -text -noout
#openssl x509 -req -in server_root.csr -out server_root_cert.pem -signkey server_root_priv.pem -days 3333
#openssl x509 -text -in server_root_cert.pem

#server_root_PWD=scap12
#openssl pkcs12 -export -in server_root_cert.pem -inkey server_root_priv.pem -passout pass:$server_root_PWD -out server_root.p12
#keytool -importkeystore -srckeystore server_root.p12 -srcstoretype pkcs12  -srcstorepass $server_root_PWD -destkeystore server_root.jks -deststoretype jks -deststorepass $server_root_PWD
## }

#server intermediate ca {
openssl ecparam -genkey -name prime256v1 -noout -out server_intermediate_priv.pem
openssl ec -in server_intermediate_priv.pem -pubout -out server_intermediate_pub.pem
openssl req -new -key server_intermediate_priv.pem -out server_intermediate.csr -sha256 -config server_intermediate.cnf
openssl req -verify -in server_intermediate.csr -text -noout
openssl x509 -req -in server_intermediate.csr -CA server_root_cert.pem -CAkey server_root_priv.pem -CAcreateserial -out server_intermediate_cert.pem -days 2222 -sha256 -extfile server_intermediate_ext.cnf
openssl x509 -text -in server_intermediate_cert.pem

server_INTERMEDIATE_PWD=sintermediatep12
openssl pkcs12 -export -in server_intermediate_cert.pem -inkey server_intermediate_priv.pem -passout pass:$server_INTERMEDIATE_PWD -out server_intermediate.p12
keytool -importkeystore -srckeystore server_intermediate.p12 -srcstoretype PKCS12  -srcstorepass $server_INTERMEDIATE_PWD -destkeystore server_intermediate.jks -deststoretype JKS -deststorepass $server_INTERMEDIATE_PWD
#}

## server ee {
#openssl ecparam -genkey -name prime256v1  -noout -out server_ee_priv.pem
#openssl pkey -in server_ee_priv.pem -pubout -out server_ee_pub.pem
#openssl req -new -sha256 -nodes -out server_ee.csr -key server_ee_priv.pem -config server_ee.cnf
#openssl req -verify -in server_ee.csr -text -noout
#openssl x509 -req -in server_ee.csr -CA server_root_cert.pem -CAkey server_root_priv.pem -CAcreateserial -out server_ee_cert.pem -days 1111 -sha256 -extfile server_ee_ext.cnf
#openssl x509 -text -in server_ee_cert.pem

#SERVER_EE_PWD=seep12
#openssl pkcs12 -export -in server_ee_cert.pem -inkey server_ee_priv.pem -passout pass:$SERVER_EE_PWD -out server_ee.p12
#keytool -importkeystore -srckeystore server_ee.p12 -srcstoretype PKCS12  -srcstorepass $SERVER_EE_PWD -destkeystore server_ee.jks -deststoretype JKS -deststorepass $SERVER_EE_PWD

#cat server_ee_cert.pem server_root_cert.pem > server_ee_cert_chain.pem
##}


##client root ca {
#openssl ecparam -genkey -name prime256v1 -noout -out client_root_priv.pem
#openssl ec -in client_root_priv.pem -pubout -out client_root_pub.pem
#openssl req -new -key client_root_priv.pem -out client_root.csr -sha256 -config client_root.cnf
#openssl req -verify -in client_root.csr -text -noout
#openssl x509 -req -in client_root.csr -out client_root_cert.pem -signkey client_root_priv.pem -days 3333
#openssl x509 -text -in client_root_cert.pem

#client_root_PWD=ccap12
#openssl pkcs12 -export -in client_root_cert.pem -inkey client_root_priv.pem -passout pass:$client_root_PWD -out client_root.p12
#keytool -importkeystore -srckeystore client_root.p12 -srcstoretype PKCS12  -srcstorepass $client_root_PWD -destkeystore client_root.jks -deststoretype JKS -deststorepass $client_root_PWD
##}

#client intermediate ca {
openssl ecparam -genkey -name prime256v1 -noout -out client_intermediate_priv.pem
openssl ec -in client_intermediate_priv.pem -pubout -out client_intermediate_pub.pem
openssl req -new -key client_intermediate_priv.pem -out client_intermediate.csr -sha256 -config client_intermediate.cnf
openssl req -verify -in client_intermediate.csr -text -noout
openssl x509 -req -in client_intermediate.csr -CA client_root_cert.pem -CAkey client_root_priv.pem -CAcreateserial -out client_intermediate_cert.pem -days 2222 -sha256 -extfile client_intermediate_ext.cnf
openssl x509 -text -in client_intermediate_cert.pem

CLIENT_INTERMEDIATE_PWD=cintermediatep12
openssl pkcs12 -export -in client_intermediate_cert.pem -inkey client_intermediate_priv.pem -passout pass:$CLIENT_INTERMEDIATE_PWD -out client_intermediate.p12
keytool -importkeystore -srckeystore client_intermediate.p12 -srcstoretype PKCS12  -srcstorepass $CLIENT_INTERMEDIATE_PWD -destkeystore client_intermediate.jks -deststoretype JKS -deststorepass $CLIENT_INTERMEDIATE_PWD
#}

#client ee {
openssl ecparam -genkey -name prime256v1 -noout -out client_ee_priv.pem
openssl pkey -in client_ee_priv.pem -pubout -out client_ee_pub.pem
openssl req -new -sha256 -nodes -out client_ee.csr -key client_ee_priv.pem -config client_ee.cnf
openssl req -verify -in client_ee.csr -text -noout
openssl x509 -req -in client_ee.csr -CA client_intermediate_cert.pem -CAkey client_intermediate_priv.pem -CAcreateserial -out client_ee_cert.pem -days 1111 -sha256 -extfile client_ee_ext.cnf
openssl x509 -text -in client_ee_cert.pem

CLIENT_EE_PWD=ceep12
openssl pkcs12 -export -in client_ee_cert.pem -inkey client_ee_priv.pem -passout pass:$CLIENT_EE_PWD -out client_ee.p12
keytool -importkeystore -srckeystore client_ee.p12 -srcstoretype PKCS12  -srcstorepass $CLIENT_EE_PWD -destkeystore client_ee.jks -deststoretype JKS -deststorepass $CLIENT_EE_PWD

cat client_ee_cert.pem client_intermediate_cert.pem client_root_cert.pem > client_ee_cert_chain.pem
cat client_intermediate_cert.pem client_root_cert.pem > client_ca_cert_chain.pem
#}
