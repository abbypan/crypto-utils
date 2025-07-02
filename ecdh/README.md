# ecdh

see also 

https://github.com/alexkrontiris/OpenSSL-x25519-key_exchange

https://www.openssl.org/docs/man1.0.2/man3/EVP_PKEY_derive.html

# install

$ make

#  x25519_keypair

    $ ./x25519_keypair x25519_a_priv.pem x25519_a_pub.pem
    $ openssl pkey -text -in x25519_a_priv.pem
    $ openssl pkey -text -pubin -in x25519_a_pub.pem

    $ ./x25519_keypair x25519_b_priv.pem x25519_b_pub.pem
    $ openssl pkey -text -in x25519_b_priv.pem
    $ openssl pkey -text -pubin -in x25519_b_pub.pem

# ecdh

    ./ecdh x25519_a_priv.pem x25519_b_pub.pem 
    ./ecdh x25519_b_priv.pem x25519_a_pub.pem 

# ecdh_ephemeral_key

    ./ecdh_ephemeral_key

will write `ephemeral_[a|b]_[private|public].pem`
