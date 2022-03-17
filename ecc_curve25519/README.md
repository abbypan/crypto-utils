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
    
    $ ./ec_pub_key2 prime256v1 259CB35D781B478BF785DE062E1A3577348290BC05E36F3B42B496CF59BF03E9 65FB768014225FB520B5CBFC2F52240CD80536CAC8716412EA1AF78D4962C0AF ec_prime256v1_pub.pem

    $ ./ec_pub_key3 prime256v1 03259CB35D781B478BF785DE062E1A3577348290BC05E36F3B42B496CF59BF03E9 ec_prime256v1_pub.compressed.pem
    $ ./ec_pub_key3 prime256v1 04259CB35D781B478BF785DE062E1A3577348290BC05E36F3B42B496CF59BF03E965FB768014225FB520B5CBFC2F52240CD80536CAC8716412EA1AF78D4962C0AF ec_prime256v1_pub.uncompressed.pem
    
    $ ./ec_pub_key_read ec_prime256v1_pub.pem

## ed25519

    $ openssl dgst -sha512 -binary plain.bin > plain.sha512.dgst
    $ ./eddsa_sign ec_priv_key.ed25519.priv.pem plain.sha512.dgst plain.ed25519.sig
    $ ./eddsa_verify ec_priv_key.ed25519.pub.pem plain.sha512.dgst plain.ed25519.sig    

## ed448
    
    $ ./eddsa_sign ec_priv_key.ed448.priv.pem plain.ed448.bin plain.ed448.sig
    $ ./eddsa_verify ec_priv_key.ed448.pub.pem plain.ed448.bin plain.ed448.sig    
    
