#!/usr/bin/perl
#see also: https://www.di-mgt.com.au/xmldsig.html
use strict;
use warnings;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;
use MIME::Base64 qw/decode_base64/;
use File::Slurp qw/write_file/;

my $n_base64='4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqCUQ8wgL6xUJ5GRPEsu9gyz8ZobwfZsGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm+Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=';
my $e_base64 = 'AQAB';

my $sig_base64 = 'nihUFQg4mDhLgecvhIcKb9Gz8VRTOlw+adiZOBBXgK4JodEe5aFfCqm8WcRIT8GLLXSk8PsUP4//SsKqUBQkpotcAqQAhtz2v9kCWdoUDnAOtFZkd/CnsZ1sge0ndha40wWDV+nOWyJxkYgicvB8POYtSmldLLepPGMz+J7/Uws=';
my $sign_info='<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>
  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>
  <Reference URI="#object">
    <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>
    <DigestValue>OPnpF/ZNLDxJ/I+1F3iHhlmSwgo=</DigestValue>
  </Reference>
</SignedInfo>';

my $pub_f = 'rsa_public.pem';

my $n       = Crypt::OpenSSL::Bignum->new_from_hex( unpack("H*", decode_base64($n_base64)) );
my $e = Crypt::OpenSSL::Bignum->new_from_hex( unpack("H*", decode_base64($e_base64)) );

my $rsa_pub = Crypt::OpenSSL::RSA->new_key_from_parameters(
    $n,
    $e,
);
$rsa_pub->use_no_padding();


my $public_s = $rsa_pub->get_public_key_x509_string();
write_file($pub_f, $public_s);

my $sig_f = 'sig.bin';
write_file($sig_f, decode_base64($sig_base64));

my $sign_info_f = 'sign_info.txt';
write_file($sign_info_f, { binmode => 'raw:'},   $sign_info);

#verify with sign_info
system(qq[openssl dgst -sha1 -verify rsa_public.pem -signature $sig_f $sign_info_f]);

#verify with digest of sign_info
my $digest_f = 'digest.bin';
system(qq[openssl dgst -sha1 -binary $sign_info_f > $digest_f]);
system(qq[openssl pkeyutl -verify -pubin -inkey $pub_f -sigfile $sig_f -in $digest_f -pkeyopt rsa_padding_mode:pkcs1 -pkeyopt digest:sha1]);
