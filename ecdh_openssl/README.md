# install

$ make

#  x25519_keypair

    ./x25519_keypair x25519_a_priv.pem x25519_a_pub.pem
    ./x25519_keypair x25519_b_priv.pem x25519_b_pub.pem

# ecdh

    ./ecdh x25519_a_priv.pem x25519_b_pub.pem 
    ./ecdh x25519_b_priv.pem x25519_a_pub.pem 

# ecdh_ephemeral_key

    ./ecdh_ephemeral_key

will write `ephemeral_[a|b]_[private|public].pem`
