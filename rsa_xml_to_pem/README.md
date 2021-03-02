# rsa_convert_xml_pem
RSA Key Converter

## install

    apt-get install perl cpanminus openssl

    cpanm -n Crypt::OpenSSL::RSA
    cpanm -n Crypt::OpenSSL::Bignum
    cpanm -n File::Slurp
    cpanm -n MIME::Base64

## generate pem

    openssl genrsa -out rsa_priv.pem 2048
    openssl rsa -in rsa_priv.pem -pubout > rsa_pub.pem

## pem to xml

    perl pem2xml.pl rsa_priv.pem test.priv.xml
    perl pem2xml.pl rsa_pub.pem test.pub.xml

## xml to pem

    perl xml2pem.pl test.priv.xml test.priv.pem
    perl xml2pem.pl test.pub.xml test.pub.pem
