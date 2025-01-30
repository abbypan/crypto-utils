# KMAC

https://docs.openssl.org/3.4/man7/EVP_MAC-KMAC/

https://github.com/openssl/openssl/blob/master/test/recipes/30-test_evp_data/evpmac_common.txt

## install

    gcc kmac-128.c -o kmac-128 -lssl -lcrypto

## kmac-128

    $ ./kmac-128 404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F 00010203 "My Tagged Application" 1 32
    key: 404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
    data: 00010203
    custom: My Tagged Application
    xof_enable: 1
    mac_len: 32
    kmac-128: 31:A4:45:27:B4:ED:9F:5C:61:01:D1:1D:E6:D2:6F:06:20:AA:5C:34:1D:EF:41:29:96:57:FE:9D:F1:A3:B1:6C

