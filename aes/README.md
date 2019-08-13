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


