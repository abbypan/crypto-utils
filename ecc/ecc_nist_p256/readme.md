ecdsa sample (nist p256)

# genkey

    openssl ecparam -genkey -name prime256v1 -out ecc_nist_p256_priv.pem
    openssl ec -in ecc_nist_p256_priv.pem -pubout -out ecc_nist_p256_pub.pem

# test with newline

    openssl dgst -sha256 -sign ecc_nist_p256_priv.pem -out test.file.sig test.txt
    openssl dgst -sha256 -verify ecc_nist_p256_pub.pem -signature test.file.sig test.txt

# test without newline

    echo -n 'abcdefg' | openssl dgst -sha256 -sign ecc_nist_p256_priv.pem -out test.msg.sig
    echo -n 'abcdefg' | openssl dgst -sha256 -verify ecc_nist_p256_pub.pem -signature test.msg.sig
