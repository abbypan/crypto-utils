#!/usr/bin/perl
use strict;
use warnings;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;

use File::Slurp qw/write_file/;

my ( $dst_pem, @priv_data_hex ) = @ARGV;

#@priv_data_hex : n, e, d, p, q
my @priv_data = map { $_=~/\S/ ?  Crypt::OpenSSL::Bignum->new_from_hex( $_ ) : undef } @priv_data_hex;

my $rsa_private = Crypt::OpenSSL::RSA->new_key_from_parameters(@priv_data);

$rsa_private->use_no_padding();

my $priv_s = $rsa_private->get_private_key_string();
write_file( $dst_pem, $priv_s );
