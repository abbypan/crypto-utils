# x9.63 kdf

## doc 

sec 1: https://www.secg.org/sec1-v2.pdf

## perl 

    $ cpan Digest
    $ perl x9.63_kdf.pl "input key" "ANSI X9.63 Example" 99 "SHA-256"
    e232c1da499317cdc90bece39e37cadc2322eb32c3c921fb24283dde34794ff5342b73c495ea7d036a7c708fe98d50f2b56b7033e5f2e2df7361208aa01f008b7403e057cf735ca39f2af77a84766c2a82d7f6376d2c4b83e73b889ff73c2e83d1f4a5

## python

https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/

    $ pip install hexdump
    $ python x9.63_kdf.py
