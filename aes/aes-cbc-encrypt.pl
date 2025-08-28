#!/usr/bin/perl -w

use strict;
use warnings;

use Crypt::CBC;

my ( $key_hex, $iv_hex, $plain_hex ) = @ARGV;

my $cipher_hex = aes_cbc_encrypt( $key_hex, $iv_hex, $plain_hex );

print "key: $key_hex\niv: $iv_hex\nplain: $plain_hex\ncipher: $cipher_hex\n";

sub aes_cbc_encrypt {
  my ( $key_hex, $iv_hex, $plain_hex ) = @_;

  my $key = pack( 'H*', $key_hex );

  my $cipher = Crypt::CBC->new(
    -key         => $key,
    -iv          => pack( 'H*', $iv_hex ),
    -cipher      => 'OpenSSL::AES',
    -literal_key => 1,
    -header      => "none",
    -padding     => "standard",        #PKCS5/PKCS7
    -keysize     => length( $key ),
  );

  my $cipher_b   = $cipher->encrypt( pack( 'H*', $plain_hex ) );
  my $cipher_hex = unpack( 'H*', $cipher_b );

  return $cipher_hex;
} ## end sub aes_cbc_encrypt
