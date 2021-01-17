#!/bin/bash

#gcc -lmbedtls -lmbedcrypto -lmbedx509 $1 -o $2
gcc -lmbedtls -lmbedcrypto -lmbedx509 ecies.c -o ecies
./ecies | tee ecies.log

