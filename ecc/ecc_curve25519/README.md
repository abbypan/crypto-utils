# ecc_curve25519

openssl ecc curve 25519 example

## prepare

    openssl dgst -sha256 -binary plain.txt > plain.sha256

    make

## ed25519

    ./ed25519_keypair ed25519_priv.txt ed25519_pub.txt

    ./ed25519_sign ed25519_priv.txt plain.sha256 plain.sig
   
    ./ed25519_verify ed25519_pub.txt plain.sha256 plain.sig    

## x25519

see also [OpenSSL-x25519-key_exchange](https://github.com/alexkrontiris/OpenSSL-x25519-key_exchange)
