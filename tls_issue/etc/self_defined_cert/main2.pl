#!/usr/bin/perl
use strict;
use warnings;

#my $s_root = generate_root_ca('server_root', 3333, 'srootpkcs12');
#my $s_int = generate_lower_cert('server_intermediate', 2222, 'sintpkcs12', "$s_root.priv.pem", "$s_root.cert.pem");
#my $s_ee = generate_lower_cert('server_ee', 1111, 'seepkcs12', "$s_int.priv.pem", "$s_int.cert.pem");
#system(qq[cat $s_ee.cert.pem $s_int.cert.pem $s_root.cert.pem > $s_ee.cert_chain.ee.pem]);
#system(qq[cat $s_int.cert.pem $s_root.cert.pem > $s_ee.cert_chain.pem]);
#system(qq[cat $s_int.cert.pem > $s_ee.cert_chain.int.pem]);
#system(qq[openssl pkcs12 -export -in $s_ee.cert_chain.ee.pem -inkey $s_ee.priv.pem -passout pass:seepkcs12 -out $s_ee.cert_chain.p12]);

my $c_root = generate_root_ca('client2_root', 3333, 'crootpkcs12');
my $c_int = generate_lower_cert('client2_intermediate', 2222, 'cintpkcs12', "$c_root.priv.pem", "$c_root.cert.pem");
my $c_ee = generate_lower_cert('client2_ee', 1111, 'ceepkcs12', "$c_int.priv.pem", "$c_int.cert.pem");
system(qq[cat $c_ee.cert.pem $c_int.cert.pem $c_root.cert.pem > $c_ee.cert_chain.ee.pem]);
system(qq[cat $c_int.cert.pem $c_root.cert.pem > $c_ee.cert_chain.pem]);
system(qq[cat $c_int.cert.pem > $c_ee.cert_chain.int.pem]);
system(qq[openssl pkcs12 -export -in $c_ee.cert_chain.ee.pem -inkey $c_ee.priv.pem -passout pass:ceepkcs12 -out $c_ee.cert_chain.p12]);

sub generate_root_ca {
    my ($prefix, $day, $pwd) = @_;

    system(qq[openssl ecparam -genkey -name secp384r1 -noout -out $prefix.priv.pem]);
    system(qq[openssl pkcs8 -topk8 -inform pem -in $prefix.priv.pem -outform pem -nocrypt -out $prefix.priv.pkcs8.pem]);
    system(qq[openssl ec -in $prefix.priv.pem -pubout -out $prefix.pub.pem]);

    system(qq[openssl req -new -key $prefix.priv.pem -out $prefix.csr -sha384 -config $prefix.cnf]);
    system(qq[openssl req -verify -in $prefix.csr -text -noout]);
    system(qq[openssl x509 -req -in $prefix.csr -out $prefix.cert.pem -signkey $prefix.priv.pem -days $day -sha384 -extfile $prefix.ext.cnf]);
    system(qq[openssl x509 -text -in $prefix.cert.pem]);

    system(qq[openssl pkcs12 -export -in $prefix.cert.pem -inkey $prefix.priv.pem -passout pass:$pwd -out $prefix.p12]);
    #system(qq[keytool -importkeystore -srckeystore $prefix.p12 -srcstoretype pkcs12  -srcstorepass $pwd -destkeystore $prefix.jks -deststoretype jks -deststorepass $pwd]);
    
    return $prefix;
}

sub generate_lower_cert {
    my ($prefix, $day, $pwd, $signer_key, $signer_cert) = @_;

    system(qq[openssl ecparam -genkey -name secp384r1 -noout -out $prefix.priv.pem]);
    system(qq[openssl pkcs8 -topk8 -inform pem -in $prefix.priv.pem -outform pem -nocrypt -out $prefix.priv.pkcs8.pem]);
    system(qq[openssl ec -in $prefix.priv.pem -pubout -out $prefix.pub.pem]);

    system(qq[openssl req -new -key $prefix.priv.pem -out $prefix.csr -sha384 -config $prefix.cnf]);
    system(qq[openssl req -verify -in $prefix.csr -text -noout]);
    system(qq[openssl x509 -req -in $prefix.csr -out $prefix.cert.pem -CA $signer_cert -CAkey $signer_key -CAcreateserial  -days $day -sha384 -extfile $prefix.ext.cnf]);
    system(qq[openssl x509 -text -in $prefix.cert.pem]);

    system(qq[openssl pkcs12 -export -in $prefix.cert.pem -inkey $prefix.priv.pem -passout pass:$pwd -out $prefix.p12]);
    #system(qq[keytool -importkeystore -srckeystore $prefix.p12 -srcstoretype pkcs12  -srcstorepass $pwd -destkeystore $prefix.jks -deststoretype jks -deststorepass $pwd]);

    return $prefix;
}

