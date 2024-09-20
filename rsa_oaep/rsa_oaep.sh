#!/bin/bash

#openssl genrsa -out rsa_priv.pem 3072
#openssl rsa -in rsa_priv.pem -pubout > rsa_pub.pem

openssl pkeyutl -in test.txt -out test.enc -inkey rsa_pub.pem -keyform PEM -pubin -encrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1

openssl pkeyutl -in test.enc -out test.dec -inkey rsa_priv.pem -keyform PEM -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1
