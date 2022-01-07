#!/usr/bin/perl
# apple platform security, find my: https://support.apple.com/guide/security/welcome/web

use strict;
use warnings;
use bigint;
use Smart::Comments;

use Crypt::Perl::BigInt;
use Crypt::Perl::ECDSA::EC::Curve;
use Crypt::Perl::ECDSA::EC::DB;
use Crypt::Perl::ECDSA::EncodedPoint;
use Crypt::Perl::ECDSA::EC::Point;
use Crypt::Perl::Math;
use Crypt::Perl::ECDSA::Generate ();
#use Crypt::Perl::RNG ();
#use Crypt::Perl::ECDSA::PrivateKey ();
#use Crypt::Perl::ECDSA::Utils;
use Digest::SHA qw/sha256/;
use Crypt::KeyDerivation ':all';
use Digest::SHA qw/hmac_sha256/;
use File::Slurp qw/slurp write_file/;
use Crypt::Random qw( makerandom_octet );
use Crypt::KeyDerivation ':all';

# { init
our $curve_name = 'secp224r1';
our $curve_hr   = Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_name( $curve_name );
our $curve      = Crypt::Perl::ECDSA::EC::Curve->new( @{$curve_hr}{ 'p', 'a', 'b' } );
our $G          = $curve->decode_point( @{$curve_hr}{ 'gx', 'gy' } );

my $d     = Crypt::Perl::ECDSA::Generate::by_curve_name( $curve_name );
my $d_pem = $d->to_pem_with_curve_name();
write_file( 'd_private.pem', $d_pem );
### $d_pem
#my $d_expc_pem = $d->to_pem_with_explicit_curve();
#write_file('private_expc.pem', $d_expc_pem);

my $P            = $d->get_public_key();
my $p_pem_header = $P->_PEM_HEADER();
### $p_pem_header
my $P_pem = $P->to_pem_with_curve_name();
write_file( 'P_public.pem', $P_pem );
### $P_pem

my $sk      = makerandom_octet( Size => 255, Strength => 1 );
my $counter = Crypt::Perl::BigInt->new();
### sk: unpack("H*", $sk)
### counter: $counter->as_hex()
# }

my ( $max_counter ) = @ARGV;
$max_counter //= 5;

for ( 1 .. $max_counter ) {
  my ( $u, $v ) = sk_iterate( \$sk, $counter );

  my $d_i     = calc_d_i( $curve_name, $d, $u, $v );
  my $d_i_pem = $d_i->to_pem_with_curve_name();
  write_file( 'd_' . $counter->to_oct() . '_private.pem', $d_i_pem );
  ### d_i_pem: $d_i_pem

  my $P_i     = calc_P_i( $curve_name, $P, $u, $v );
  my $P_i_pem = $P_i->to_pem_with_curve_name();
  write_file( 'P_' . $counter->to_oct() . '_public.pem', $P_i_pem );
  ### P_i_pem: $P_i_pem
}

sub calc_P_i {
  my ( $curve_name, $P, $u, $v ) = @_;

  my $P_Point     = parse_encoded_ec_point( $curve_hr, $curve, $P->{_public}{_bin} );
  my $P_i_Point   = $P_Point->multiply( $u )->add( $G->multiply( $v ) );
  my $P_i_encoded = encode_ec_point( $curve_hr, $P_i_Point );
  ### P_i_encoded: unpack("H*", $P_i_encoded)
  my $P_i_encoded_Point = Crypt::Perl::ECDSA::EncodedPoint->new( $P_i_encoded );
  my $P_i               = { _public => $P_i_encoded_Point, curve => $curve_hr };
  bless $P_i, 'Crypt::Perl::ECDSA::PublicKey';

  return $P_i;
}

sub calc_d_i {
  my ( $curve_name, $d, $u, $v ) = @_;

  #my $curve_hr = Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_name( $curve_name );

  my $s = $d->{private}->copy()->bmul( $u )->badd( $v )->bmod( $curve_hr->{n} );

  my $d_i = generate_private_key( $curve_name, $s );
  ### d_i: $s->as_hex()

  return $d_i;
}

sub generate_private_key {
  my ( $curve_name, $biPrv ) = @_;

  #my $biN = $curve_hr->{'n'};
  #my $biPrv = Crypt::Perl::Math::randint( $biN );

  #my $G = '04' . join(q<>, map { substr( $_->as_hex(), 2 ) } @{$curve}{'gx','gy'});
  #$G = Crypt::Perl::BigInt->from_hex($full_g);

  #my $curve_hr = Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_name( $curve_name );
  #my $curve    = Crypt::Perl::ECDSA::EC::Curve->new( @{$curve_hr}{ 'p', 'a', 'b' } );

  #my $G = $curve->decode_point( @{$curve_hr}{ 'gx', 'gy' } );

  my $epPub = $G->multiply( $biPrv );
  my $biX   = $epPub->get_x()->to_bigint();
  my $biY   = $epPub->get_y()->to_bigint();

  my $key_hex_len = 2 * Crypt::Perl::Math::ceil( $curve->keylen() / 8 );

  my ( $hx, $hy ) = map { substr( $_->as_hex(), 2 ) } $biX, $biY;

  $_ = sprintf "%0${key_hex_len}s", $_ for ( $hx, $hy );

  my $biPub = Crypt::Perl::BigInt->from_hex( "04$hx$hy" );

  my $key_parts = {
    version => 0,
    private => $biPrv,
    public  => $biPub,
  };

  my $prkey = Crypt::Perl::ECDSA::PrivateKey->new_by_curve_name( $key_parts, $curve_name );
  return $prkey;
} ## end sub generate_private_key

sub sk_iterate {
  my ( $sk_r, $counter ) = @_;

  $counter->binc();
  $$sk_r = hkdf( $$sk_r, '', 'SHA256', 32, 'update' );
  ### sk: unpack("H*", $$sk_r)
  ### counter: $counter->as_hex()

  my $s = hkdf( $$sk_r, '', 'SHA256', 32, 'diversify' );
  ### u, v: unpack("H*", $s)
  my $u    = substr $s, 0, 16;
  my $v    = substr $s, 16;
  my $u_bn = Crypt::Perl::BigInt->from_hex( unpack( "H*", $u ) );
  my $v_bn = Crypt::Perl::BigInt->from_hex( unpack( "H*", $v ) );
  ### u: $u_bn->as_hex()
  ### v: $v_bn->as_hex()

  return ( $u_bn, $v_bn );
} ## end sub sk_iterate

sub parse_encoded_ec_point {
  my ( $curve_hr, $curve, $point_s ) = @_;
  my $point      = Crypt::Perl::ECDSA::EncodedPoint->new( $point_s );
  my $point_un_s = $point->get_uncompressed( $curve_hr );
  my $len        = ( length( $point_un_s ) - 1 ) / 2;
  my $x          = substr $point_un_s, 1, $len;
  my $y          = substr $point_un_s, $len + 1;

  my $x_int = Crypt::Perl::BigInt->from_hex( unpack( "H*", $x ) );
  my $y_int = Crypt::Perl::BigInt->from_hex( unpack( "H*", $y ) );
  my $x_fe  = $curve->from_bigint( $x_int );
  my $y_fe  = $curve->from_bigint( $y_int );

  my $ec_point = Crypt::Perl::ECDSA::EC::Point->new(
    $curve,
    $x_fe, $y_fe,
  );

  return $ec_point;
} ## end sub parse_encoded_ec_point

sub encode_ec_point {
  my ( $curve_hr, $point ) = @_;

  #my $curve = Crypt::Perl::ECDSA::EC::Curve->new( @{$curve_hr}{ 'p', 'a', 'b' } );
  my $biX = $point->get_x()->to_bigint();
  my $biY = $point->get_y()->to_bigint();

  my $key_hex_len = 2 * Crypt::Perl::Math::ceil( $curve->keylen() / 8 );

  my ( $hx, $hy ) = map { substr( $_->as_hex(), 2 ) } $biX, $biY;
  $_ = sprintf "%0${key_hex_len}s", $_ for ( $hx, $hy );

  my $s = pack( "H*", join( '', '04', $hx, $hy ) );
  return $s;
}
