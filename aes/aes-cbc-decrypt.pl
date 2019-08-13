#!/usr/bin/perl -w

use strict;
use warnings;

use Crypt::CBC;

my ( $key_hex, $iv_hex, $cipher_hex ) = @ARGV;

my $plain_hex = aes_cbc_decrypt( $key_hex, $iv_hex, $cipher_hex );

print "key: $key_hex\niv: $iv_hex\ncipher: $cipher_hex\nplain: $plain_hex\n";

sub aes_cbc_decrypt {
  my ( $key_hex, $iv_hex, $cipher_hex ) = @_;

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

  my $plain_b   = $cipher->decrypt( pack( 'H*', $cipher_hex ) );
  my $plain_hex = unpack( 'H*', $plain_b );

  return $plain_hex;
} ## end sub aes_cbc_decrypt
