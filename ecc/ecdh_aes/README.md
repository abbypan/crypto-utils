# ecdh_aes

# ECDH + AES hybrid encryption

see also: https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption.html


    $ python ecdh_aes.py

    original msg:
     b'fortest'

    encrypt:
    ciphertextPrivKey: 0x6845ae8dc0ca67458eae22281a03334dbf5411b53d36131cb7dfd1da757e8269
    pubKey: 0x53c3837fa6ebdc5e5c41ed348349727d9430f670b51339780fc9296293452e6, 0xa7e2c85d42a9fdcd5b6ca8a1c648c6587e35ba0110416ef471b7c933931ff54f
    sharedECCKey: 0x27cd6583bb0697bcd3b5f5be253ba835f7b9ef5065b371132db059c17550e8e0, 0x2bb05f24a368c4b3f814e8202c4c92d95563d23ec921a05d4bbc2ff7cd47928a
    AES secretKey: c2a24a0ad80856618cf8f9738366649f

    ciphertext: 2e4371e89721bc
    nonce: a82eb4a0d6808bb5899e9734018ba43b
    authTag: b9e4df136955dc9515b23334791ca81c
    ciphertextPubKey: 0x1a20d248c3801c3976f86bc894131280e04d3dba10bf2ef0866b1b33329f5401, 0x96625e1cd5895516e43b257d2c536b42897edd9b256764da427932311f8c05f

    decrypt:
    privKey: 0x9ee0509b5bbce32d864751964a35a6703cf6f42c5c6a74b80fded0b9858cc39c
    sharedECCKey: 0x27cd6583bb0697bcd3b5f5be253ba835f7b9ef5065b371132db059c17550e8e0, 0x2bb05f24a368c4b3f814e8202c4c92d95563d23ec921a05d4bbc2ff7cd47928a
    AES secretKey: c2a24a0ad80856618cf8f9738366649f

    decrypted msg:
     b'fortest'
     
# ECDH + simple AES hybrid encryption
     
    $ python ecdh_aes2.py 

    original msg: b'fortest'

    alice ecdh key: 0xd124a39a1154312a197fa3a28ce84febe8be00c5684cbe802580e34d2d34d4e , 0x94f316915f41498d2903b7e275efef1d119e36999910818ae058717059312337
    alice gcm key: d124a39a1154312a197fa3a28ce84feb , alice gcm iv: 94f316915f41498d2903b7e2

    alice ciphertext: b'877b784ed411aa'
    alice authTag: b'32526061975348f56e9bc6646cefbe4e'

    bob ecdh key: 0xd124a39a1154312a197fa3a28ce84febe8be00c5684cbe802580e34d2d34d4e , 0x94f316915f41498d2903b7e275efef1d119e36999910818ae058717059312337
    bob gcm key: d124a39a1154312a197fa3a28ce84feb , bob gcm iv: 94f316915f41498d2903b7e2

    bob decrypt plaintext: b'fortest'

