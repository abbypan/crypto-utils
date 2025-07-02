# ecies

gcc -lmbedtls -lmbedcrypto -lmbedx509 ecies.c -o ecies

./ecies | tee ecies.log
