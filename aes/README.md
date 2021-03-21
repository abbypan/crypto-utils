# aes sample

# install

    apt-get install openssl perl cpanminus
    cpanm Crypt::CBC

# aes-cbc

use default PKCS5/PKCS7 padding

perl aes-cbc-encrypt.pl [key_hex] [iv_hex] [plain_hex]

    $ perl aes-cbc-encrypt.pl 59e7866e936b8f4f4bcca03fe7de8148 762892918be716e7a169c7177a1697a1 0102ff0304
    key: 59e7866e936b8f4f4bcca03fe7de8148
    iv: 762892918be716e7a169c7177a1697a1
    plain: 0102ff0304
    cipher: 9e1e545ebb43d11f25f99b2709d8a714

perl aes-cbc-decrypt.pl [key_hex] [iv_hex] [cipher_hex]

    $ perl aes-cbc-decrypt.pl 59e7866e936b8f4f4bcca03fe7de8148 762892918be716e7a169c7177a1697a1 9e1e545ebb43d11f25f99b2709d8a714
    key: 59e7866e936b8f4f4bcca03fe7de8148
    iv: 762892918be716e7a169c7177a1697a1
    cipher: 9e1e545ebb43d11f25f99b2709d8a714
    plain: 0102ff0304


# aes-gcm with aad

    gcc -lmbedtls -lmbedcrypto -lmbedx509 aes-gcm-aad-encrypt.c -o aes-gcm-aad-encrypt
    ./aes-gcm-aad-encrypt 6e4d19cc35eb977bf2c33a2de9d51e3d794702ca6b87105ae1874b18f5e1db6f b79e546d643b1d3a935d1377 somedevice.context plain.txt cipher.bin authtag.bin

    gcc -lmbedtls -lmbedcrypto -lmbedx509 aes-gcm-aad-decrypt.c -o aes-gcm-aad-decrypt
    ./aes-gcm-aad-decrypt 6e4d19cc35eb977bf2c33a2de9d51e3d794702ca6b87105ae1874b18f5e1db6f b79e546d643b1d3a935d1377 somedevice.context cipher.bin authtag.bin decrypt.txt
