#!/usr/bin/perl
use strict;
use warnings;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;

my ( $n_hex, $e_hex, $signature_hex ) = @ARGV;

my $em_hex = rsa_decrypt_signature( $n_hex, $e_hex, $signature_hex );
print "em: $em_hex\n";

sub rsa_decrypt_signature {
  my ( $n_hex, $e_hex, $signature_hex ) = @_;

  print "n: $n_hex\n";
  my $n       = Crypt::OpenSSL::Bignum->new_from_hex( $n_hex );
  my $modBits = $n->num_bits;
  print "modBits: $modBits\n";

  print "e: $e_hex\n";
  my $e = Crypt::OpenSSL::Bignum->new_from_hex( $e_hex );

  my $rsa_pub = Crypt::OpenSSL::RSA->new_key_from_parameters(
    $n,
    $e,
  );
  $rsa_pub->use_no_padding();

  print "signature: $signature_hex\n";
  my $signature = pack( "H*", $signature_hex );

  my $em = $rsa_pub->public_decrypt( $signature );
  $em = unpack( "H*", $em );

  return $em;
} ## end sub rsa_decrypt_signature
