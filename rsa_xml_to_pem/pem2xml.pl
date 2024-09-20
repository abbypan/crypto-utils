#!/usr/bin/perl
use strict;
use warnings;

use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;
use File::Slurp qw/slurp write_file/;
use MIME::Base64;
use Data::Dumper;

my ( $pem, $xml ) = @ARGV;
$xml ||= "$pem.xml";

my $s = slurp( $pem );
my $xml_s = $s =~ /-----BEGIN RSA PRIVATE KEY-----/s ? conv_priv( $s ) : conv_public( $s );

write_file( $xml, $xml_s );

sub conv_public {
  my ( $public_s ) = @_;
  my $rsa_public = Crypt::OpenSSL::RSA->new_public_key( $public_s );

  my %data;
  @data{qw/n e/} =
    map { $_ = encode_base64( pack( 'H*', $_->to_hex ) ); s/\n$//s; $_ } grep { $_ } $rsa_public->get_key_parameters();

  my $s = "<RSAKeyValue>
<Modulus>$data{n}</Modulus>
<Exponent>$data{e}</Exponent>
</RSAKeyValue>";

  return $s;
}

sub conv_priv {
  my ( $priv_s ) = @_;
  my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key( $priv_s );

  my %data;
  @data{qw/n e d p q dp dq invq/} =
    map { $_ = encode_base64( pack( 'H*', $_->to_hex ) ); s/\n$//s; $_ } $rsa_priv->get_key_parameters();

  my $s = "<RSAKeyValue>
<Modulus>$data{n}</Modulus>
<Exponent>$data{e}</Exponent>
<P>$data{p}</P>
<Q>$data{q}</Q>
<DP>$data{dp}</DP>
<DQ>$data{dq}</DQ>
<InverseQ>$data{invq}</InverseQ>
<D>$data{d}</D>
</RSAKeyValue>";

  return $s;
} ## end sub conv_priv
