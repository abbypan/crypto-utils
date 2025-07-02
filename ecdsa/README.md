# ecdsa

# genkey

    openssl ecparam -genkey -name prime256v1 -out ecc_nist_p256_priv.pem
    openssl ec -in ecc_nist_p256_priv.pem -pubout -out ecc_nist_p256_pub.pem

# test with newline

    openssl dgst -sha256 -sign ecc_nist_p256_priv.pem -out test.sig test.txt
    openssl dgst -sha256 -verify ecc_nist_p256_pub.pem -signature test.sig test.txt

# test without newline

    echo -n 'abcdefg' | openssl dgst -sha256 -sign ecc_nist_p256_priv.pem -out test.msg.sig
    echo -n 'abcdefg' | openssl dgst -sha256 -verify ecc_nist_p256_pub.pem -signature test.msg.sig

    echo -n 'abcdefg' | openssl dgst -sha256 -binary > test.msg.dgst
    openssl pkeyutl -verify -pubin -inkey ecc_nist_p256_pub.pem -sigfile test.msg.sig -in test.msg.dgst -pkeyopt digest:sha256

# ecdsa.py

    $ python ecdsa.py 

    msg: b'fortest'
    msg dgst:  b'7ae36d3938d986158c7601353c8de5ff499685a9ab33f424201ab0492a6b640f'
    r: 0xd4a60a1132394f7c6c878863da127de95af10cfb7cda068218528f8b249dd2dd, s: 0x61b92a4f8df9c62625ea69f812f28974608ed0c1bc0ef1899a674ac921bf7030
    signature:  3045022100D4A60A1132394F7C6C878863DA127DE95AF10CFB7CDA068218528F8B249DD2DD022061B92A4F8DF9C62625EA69F812F28974608ED0C1BC0EF1899A674AC921BF7030
    r: 0xd4a60a1132394f7c6c878863da127de95af10cfb7cda068218528f8b249dd2dd s: 0x61b92a4f8df9c62625ea69f812f28974608ed0c1bc0ef1899a674ac921bf7030
    v: 0xd4a60a1132394f7c6c878863da127de95af10cfb7cda068218528f8b249dd2dd
    True
