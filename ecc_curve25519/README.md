# ecc_curve25519

openssl ecc curve 25519 example

## prepare

    $ make

## ed25519

    $ openssl dgst -sha256 -binary plain.txt > plain.dgst

    $ ./ed25519_keypair ed25519_priv.pem ed25519_pub.pem

    $ ./ed25519_sign ed25519_priv.pem plain.dgst plain.sig
   
    $ ./ed25519_verify ed25519_pub.pem plain.dgst plain.sig    

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

