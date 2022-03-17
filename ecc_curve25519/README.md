# curve25519/curve448

RFC8032 

## prepare

    $ make

## nid

    https://github.com/openssl/openssl/blob/master/crypto/objects/obj_dat.h

## ec


    $ ./ec_priv_key ED25519 833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42 ec_priv_key.ed25519.priv.pem ec_priv_key.ed25519.pub.pem 
    $ ./ec_pub_key ED25519  ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf ec_pub_key.ed25519.pub.pem 
    $ ./ec_keypair ED25519  ed25519_priv.pem ed25519_pub.pem
    $ ./ec_keypair ED448  ed448_priv.pem ed448_pub.pem

    $ ./ec_priv_key ED448 cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328 ec_priv_key.ed448.priv.pem ec_priv_key.ed448.pub.pem

## ed25519

    $ openssl dgst -sha512 -binary plain.bin > plain.sha512.dgst
    $ ./eddsa_sign ec_priv_key.ed25519.priv.pem plain.sha512.dgst plain.ed25519.sig
    $ ./eddsa_verify ec_priv_key.ed25519.pub.pem plain.sha512.dgst plain.ed25519.sig    

## ed448
    
    $ ./eddsa_sign ec_priv_key.ed448.priv.pem plain.ed448.bin plain.ed448.sig
    $ ./eddsa_verify ec_priv_key.ed448.pub.pem plain.ed448.bin plain.ed448.sig    
    
## x25519

see also 

https://github.com/alexkrontiris/OpenSSL-x25519-key_exchange

https://www.openssl.org/docs/man1.0.2/man3/EVP_PKEY_derive.html

    $ ./x25519_keypair x25519_a_priv.pem x25519_a_pub.pem
    $ openssl pkey -text -in x25519_a_priv.pem
    $ openssl pkey -text -pubin -in x25519_a_pub.pem
    
    $ ./x25519_keypair x25519_b_priv.pem x25519_b_pub.pem
    $ openssl pkey -text -in x25519_b_priv.pem
    $ openssl pkey -text -pubin -in x25519_b_pub.pem
    
    $ ./x25519_ecdh x25519_a_priv.pem x25519_b_pub.pem

       Read Local Private Key:
       -----BEGIN PRIVATE KEY-----
       MC4CAQAwBQYDK2VuBCIEIPim2phWqGnbhZxHwPEAIVhURLp6jgDk+0RWT1hRMXtQ
       -----END PRIVATE KEY-----

       Read Peer PUBKEY Key:
       -----BEGIN PUBLIC KEY-----
       MCowBQYDK2VuAyEAAZRfhQ3dkLQe1RbLTD7SjPmJQM5aPbEi6din4V1lXkY=
       -----END PUBLIC KEY-----

       Z, 32
       0d661c303ea035be2936174fec0954213d0d7c760f67b9b661414064304a8347
       0d 66 1c 30 3e a0 35 be 
       29 36 17 4f ec 09 54 21 
       3d 0d 7c 76 0f 67 b9 b6 
       61 41 40 64 30 4a 83 47 

    $ ./x25519_ecdh x25519_b_priv.pem x25519_a_pub.pem

       Read Local Private Key:
       -----BEGIN PRIVATE KEY-----
       MC4CAQAwBQYDK2VuBCIEIChs3NWnxEqZC0HrI9x0/R3VfNPvov3xCCYkCe19AyZq
       -----END PRIVATE KEY-----

       Read Peer PUBKEY Key:
       -----BEGIN PUBLIC KEY-----
       MCowBQYDK2VuAyEAZ1IknGaWbSbdvxp11qu6zdBLnWX/5RcfzeSSol//dj4=
       -----END PUBLIC KEY-----

       Z, 32
       0d661c303ea035be2936174fec0954213d0d7c760f67b9b661414064304a8347
       0d 66 1c 30 3e a0 35 be 
       29 36 17 4f ec 09 54 21 
       3d 0d 7c 76 0f 67 b9 b6 
       61 41 40 64 30 4a 83 47 

