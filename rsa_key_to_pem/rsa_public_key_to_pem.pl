#!/usr/bin/perl
use strict;
use warnings;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;

use File::Slurp qw/write_file/;

my ( $dst_pem, $n_hex, $e_hex ) = @ARGV;

my $n = Crypt::OpenSSL::Bignum->new_from_hex( $n_hex );
my $e = Crypt::OpenSSL::Bignum->new_from_hex( $e_hex );

my $rsa_pub = Crypt::OpenSSL::RSA->new_key_from_parameters(
  $n,
  $e,
);

$rsa_pub->use_no_padding();

my $public_s = $rsa_pub->get_public_key_x509_string();
write_file( $dst_pem, $public_s );
