#!/usr/bin/perl
use strict;
use warnings;

use Crypt::OpenSSL::Bignum;
use Crypt::OpenSSL::RSA;
use Data::Dumper;
use File::Slurp qw/slurp write_file/;
use MIME::Base64;

my ( $xml, $pem ) = @ARGV;
$pem ||= "$xml.pem";

my $s = slurp( $xml );

my %data;
my @key = qw/Modulus Exponent P Q DP DQ InverseQ D/;
for my $k ( @key ) {
  my ( $v ) = $s =~ m#<$k>(.+?)</$k>#s;
  next unless ( $v );
  $data{$k} = Crypt::OpenSSL::Bignum->new_from_hex( unpack( 'H*', decode_base64( $v ) ) );
}

my $write_s;
if ( exists $data{D} ) {
  my $rsa = Crypt::OpenSSL::RSA->new_key_from_parameters( @data{qw/Modulus Exponent D P Q/} );
  $write_s = $rsa->get_private_key_string;
} else {
  my $rsa = Crypt::OpenSSL::RSA->new_key_from_parameters( @data{qw/Modulus Exponent/} );
  $write_s = $rsa->get_public_key_string;
}

write_file( $pem, $write_s );
