# ecc_sample
Elliptic Curve Cryptography

http://cacr.uwaterloo.ca/techreports/1999/corr99-34.pdf

https://tools.ietf.org/html/rfc5480

https://tools.ietf.org/html/rfc6979

[SEC 1: Elliptic Curve Cryptography](http://www.secg.org/sec1-v2.pdf)

# install

require python
    
    $ pip install pycryptodomex tinyec sympy

# EC ElGamal (improved version)

see also: http://zoo.cs.yale.edu/classes/cs467/2017f/lectures/ln13.pdf

use r.x for encryption, use inverse r.x for decryption

    $ python ec_elgamal_improved.py

    plain-text:
    m: 0xcdc271e654075e9567fda6cf7765dd0

    encrypt:
    k: 0x6c99c3f4e8c023f38e26fe23f390eeedafacab4be4656ff7da970dfe2a572e7b
    r: 0x6ea2842f812f462beae9be9058ee4fdf45500017de65b00a7b049e59a5452a35, 0x43517f409169db6161107b664653f5dcd5afcc417768a5df41116231d7e92f63
    cipher y1: 0x421a9145f0fd4d4933ddff39051f56e47068a66b1283bae0fcca26305fe13b1c, 0x465a537b06bab6adec8a18c05c16355a745a2eb6afd1e08fd115e42e8e5d4a21
    cipher y2: 0x144a7d861b18ea94a7c8755f9d12923c1b5dde68a1c0b411cdd494b0545f4d46

    decrypt:
    r: 0x6ea2842f812f462beae9be9058ee4fdf45500017de65b00a7b049e59a5452a35, 0x43517f409169db6161107b664653f5dcd5afcc417768a5df41116231d7e92f63
    inv of r.x: 0x8025cbed276597b07c05ade43a0b280608297288aaaa6d66473e02e45b20d704
    m: 0xcdc271e654075e9567fda6cf7765dd0

# EC ElGamal (improved version), inverse r.x for encryption

use inverse r.x for encryption, use r.x for decryption

    $ python ec_elgamal_improved2.py

    plain-text:
    m: 0xa2fa056617c1f5d197c580d100dd69f8

    encrypt:
    k: 0x2b53c15152b59155a14a8a23482243259208b8330b2bfac85c3f0c7ecba6904b
    r: 0xe7db03150dc9d73af07c6de545dd81400976560a2a78a2f688522ccfa8f51894, 0xe9594d15b2974ea7ed406209f81bc8b020820ce1874ec37bd7994ff4fec68881
    cipher y1: 0x144ca4ec646c4526757c4b23faabcc062570fb7693f5a7cc815dfe12b45eadd6, 0xfdd38545b55562b9a55dece073a37b8734516d20388ee8b6da06922921bdcfb5
    inv of r.x: 0x33732d1609aadb232d2fb402b8605b190e7850478fd86bdeb4089bcbbe1a80ad
    cipher y2: 0x29e9904ad7fe52b2d29c36216b4195c0945615e942648cf76e1ec7f45903b92

    decrypt:
    r: 0xe7db03150dc9d73af07c6de545dd81400976560a2a78a2f688522ccfa8f51894, 0xe9594d15b2974ea7ed406209f81bc8b020820ce1874ec37bd7994ff4fec68881
    m: 0xa2fa056617c1f5d197c580d100dd69f8

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


# ECDSA


    $ python ecdsa.py 

    msg: b'fortest'
    msg dgst:  b'7ae36d3938d986158c7601353c8de5ff499685a9ab33f424201ab0492a6b640f'
    r: 0xd4a60a1132394f7c6c878863da127de95af10cfb7cda068218528f8b249dd2dd, s: 0x61b92a4f8df9c62625ea69f812f28974608ed0c1bc0ef1899a674ac921bf7030
    signature:  3045022100D4A60A1132394F7C6C878863DA127DE95AF10CFB7CDA068218528F8B249DD2DD022061B92A4F8DF9C62625EA69F812F28974608ED0C1BC0EF1899A674AC921BF7030
    r: 0xd4a60a1132394f7c6c878863da127de95af10cfb7cda068218528f8b249dd2dd s: 0x61b92a4f8df9c62625ea69f812f28974608ed0c1bc0ef1899a674ac921bf7030
    v: 0xd4a60a1132394f7c6c878863da127de95af10cfb7cda068218528f8b249dd2dd
    True
