# ocsp_example
ocsp example, RFC6960

see also https://pki.goog/ policies document.

# ocsp query

ocsp query, and use tcpdump to capture the google_ocsp.cap 

    $ sudo tcpdump port 80 -w google_ocsp.cap 

    $ openssl ocsp -issuer google_chain.pem -cert google_end.pem -text -url http://ocsp.pki.goog/GTSGIAG3  | tee google_ocsp.txt

# extract issuer's public key

    $ openssl x509 -pubkey -noout -in google_issuer.pem > google_issuer_pubkey.pem

# verify ocsp response signature

We can see that Google use issuer CA to sign the ocsp response, not use a OCSP Responder whose Certificate is signed by the issuer CA.

Therefore, we can use the issuer's public key to verify the ocsp response signature

Extract the tbsResponseData and signature from google_ocsp.cap, write into raw binary file: google_ocsp_tbsResponseData.bin, google_ocsp_response_signature.bin

    $ openssl dgst -sha256 -verify google_issuer_pubkey.pem -signature google_ocsp_response_signature.bin google_ocsp_tbsResponseData.bin
    Verified OK

# generate the ocsp request: issuerNameHash, issuerKeyHash, serialNumber

serialNumber is read from google_end.pem

    $ openssl asn1parse -in google_end.pem

    $ openssl x509 -in google_end.pem -serial -noout
    serial=06DA4B6CAD3471E1D91BA403459F741D

issuerName is read from google_end.pem, write into raw binary file: google_end.pem.issuer.bin

    $ openssl dgst -sha1 google_end.pem.issuer.bin
    SHA1(google_end.pem.issuer.bin)= f6edb0636232819a35f68d75a09d024a11aa6cad 

issuerKey is read from google_issuer.pem, write into raw binary file: google_issuer.pem.subjectPublicKey.bin

    $ openssl dgst -sha1 google_issuer.pem.subjectPublicKey.bin
    SHA1(google_issuer.pem.subjectPublicKey.bin)= 77c2b8509a677676b12dc286d083a07ea67eba4b

see also ocsp_issuer_hash.pl

    $ perl ocsp_issuer_hash.pl
    Issuer Name Hash: f6edb0636232819a35f68d75a09d024a11aa6cad
    Issuer Key Hash: 77c2b8509a677676b12dc286d083a07ea67eba4b
