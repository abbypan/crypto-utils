# AES-CMAC

https://www.rfc-editor.org/rfc/rfc4493.html

## install

    gcc aes-128-cmac.c -o aes-128-cmac -lssl -lcrypto

## aes-128-cmac

    $ ./aes-128-cmac 2b7e151628aed2a6abf7158809cf4f3c 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411
    key_hexstr: 2b7e151628aed2a6abf7158809cf4f3c
    data_hexstr: 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411
    aes-128-cmac_hexstr: DF:A6:67:47:DE:9A:E6:30:30:CA:32:61:14:97:C8:27
