# crypto sample

crypto sample, pkcs, pbkdf2, openssl, aes

# install

    $ apt-get install cpanminus openssl libssl-dev
    $ cpanm -n File::Slurp PBKDF2::Tiny Crypt::CBC Digest::SHA Crypt::OpenSSL::PKCS::Func 

# openssl command

[openssl_cmd.sh](openssl_cmd/openssl_cmd.sh)

# pkcs12

[p12_asn.c](https://github.com/openssl/openssl/blob/master/crypto/pkcs12/p12_asn.c)

    password = "123456"

    $ openssl pkcs12 -export -out ttt.p12 -inkey ttt.priv.pem -in ttt.cert.pem -macalg sha256 -keypbe aes-256-cbc -certpbe aes-256-cbc -passin pass:123456 -passout pass:123456

    password encrypted PKCS12 {
        MAC: sha256, Iteration 2048
        MAC length: 32, salt length: 8
        Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256
        PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256
    }

    $ openssl pkcs12 -info -in ttt.p12 -passin pass:123456 -passout pass:123456


## Perl: [parse_pkcs12_aes256cbc_sha256.pl](pkcs12/parse_pkcs12_aes256cbc_sha256.pl)

    #p12 file, password, md algorithm, dk len
    $ perl parse_pkcs12_aes256cbc_sha256.pl ttt.p12 123456 SHA-256 32


## C, OpenSSL 1.0.1t: [parse_pkcs12_aes256cbc_sha256.c](pkcs12/parse_pkcs12_aes256cbc_sha256.c)

    # p12 file, password
    $ gcc parse_pkcs12_aes256cbc_sha256.c -lssl -lcrypto -o parse_pkcs12_aes256cbc_sha256

    $ ./parse_pkcs12_aes256cbc_sha256 ttt.p12 123456


## C, OpenSSL 3.0.0-dev: [parse_pkcs12_aes256cbc_sha256_new.c](pkcs12/parse_pkcs12_aes256cbc_sha256_new.c)

    # p12 file, password
    $ gcc parse_pkcs12_aes256cbc_sha256_new.c -lssl -lcrypto -o parse_pkcs12_aes256cbc_sha256_new

    $ ./parse_pkcs12_aes256cbc_sha256_new ttt.p12 123456

# [RSASSA-PSS](rsassa_pss/)

sample for RSA2048 + SHA256 + RSASSA-PSS
