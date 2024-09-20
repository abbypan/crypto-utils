#!/usr/bin/perl
# https://www.potaroo.net/ietf/ids/draft-bar-cfrg-spake2plus-03.html
# 'SPAKE2+-P256-SHA256-HKDF draft-01'

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

#use Crypt::Perl::RNG ();
#use Crypt::Perl::ECDSA::PrivateKey ();
#use Crypt::Perl::ECDSA::Utils;
use Digest::SHA qw/sha256/;
use Crypt::KeyDerivation ':all';
use Digest::SHA qw/hmac_sha256/;

my $curve_hr = Crypt::Perl::ECDSA::EC::DB::get_curve_data_by_name( 'prime256v1' );
## $curve_hr

my $curve = Crypt::Perl::ECDSA::EC::Curve->new( @{$curve_hr}{ 'p', 'a', 'b' } );
## $curve

my $P = $curve->decode_point( @{$curve_hr}{ 'gx', 'gy' } );

my $M       = pack( "H*", '02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f' );
my $M_Point = parse_encoded_ec_point( $curve_hr, $curve, $M );
$M = encode_ec_point( $curve_hr, $M_Point );
### M: unpack('H*', $M)

my $N       = pack( "H*", '03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49' );
my $N_Point = parse_encoded_ec_point( $curve_hr, $curve, $N );
$N = encode_ec_point( $curve_hr, $N_Point );
### N: unpack('H*', $N)

my $Context = 'SPAKE2+-P256-SHA256-HKDF draft-01';
### $Context
my $A = 'client';
### $A
my $B = 'server';
### $B

# A, B: w0, w1, L = w1*P
my $w0 = 'e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c';
### $w0
my $w0_bn = Crypt::Perl::BigInt->from_hex( $w0 );
my $w1    = '24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512';
### $w1
my $w1_bn   = Crypt::Perl::BigInt->from_hex( $w1 );
my $L_Point = $P->multiply( $w1_bn );
my $L       = encode_ec_point( $curve_hr, $L_Point );
### L: unpack('H*', $L)

# A : X = x*P + w0*M
my $x       = '8b0f3f383905cf3a3bb955ef8fb62e24849dd349a05ca79aafb18041d30cbdb6';
my $x_bn    = Crypt::Perl::BigInt->from_hex( $x );
my $X_Point = $P->multiply( $x_bn )->add( $M_Point->multiply( $w0_bn ) );
my $X       = encode_ec_point( $curve_hr, $X_Point );
### X: unpack('H*', $X)

# B : Y = y*P + w0*N
my $y       = '2e0895b0e763d6d5a9564433e64ac3cac74ff897f6c3445247ba1bab40082a91';
my $y_bn    = Crypt::Perl::BigInt->from_hex( $y );
my $Y_Point = $P->multiply( $y_bn )->add( $N_Point->multiply( $w0_bn ) );
my $Y       = encode_ec_point( $curve_hr, $Y_Point );
### Y: unpack('H*', $Y)

# A: Z = h*x*(Y - w0*N), V = h*w1*(Y - w0*N)
my $A_Calc         = $Y_Point->add( $N_Point->multiply( $w0_bn )->negate() );
my $A_Calc_Z_Point = $A_Calc->multiply( $x_bn )->multiply( $curve_hr->{h} );
my $A_Calc_Z       = encode_ec_point( $curve_hr, $A_Calc_Z_Point );
### A calc Z: unpack('H*', $A_Calc_Z)
my $A_Calc_V_Point = $A_Calc->multiply( $w1_bn )->multiply( $curve_hr->{h} );
my $A_Calc_V       = encode_ec_point( $curve_hr, $A_Calc_V_Point );
### A calc V: unpack('H*', $A_Calc_V)

# B: Z = h*y*(X - w0*M), V = h*y*L
my $B_Calc         = $X_Point->add( $M_Point->multiply( $w0_bn )->negate() );
my $B_Calc_Z_Point = $B_Calc->multiply( $y_bn )->multiply( $curve_hr->{h} );
my $B_Calc_Z       = encode_ec_point( $curve_hr, $B_Calc_Z_Point );
### B calc Z: unpack('H*', $B_Calc_Z)
my $B_Calc_V_Point = $L_Point->multiply( $y_bn )->multiply( $curve_hr->{h} );
my $B_Calc_V       = encode_ec_point( $curve_hr, $B_Calc_V_Point );
### B calc V: unpack('H*', $B_Calc_V)

# A/B calc TT
my $TT = join(
  '',
  map {
      $_ //= '';
      my $len = length( $_ );
      $len = pack 'S<4', $len;
      $len, $_;
  } ( $Context, $A, $B, $M, $N, $X, $Y, $A_Calc_Z, $A_Calc_V, pack( "H*", $w0 ) ) );

#} ($Context, $A,$B,$M,$N, $X,$Y,$B_Calc_Z,$B_Calc_V,pack("H*", $w0)));
### TT: unpack("H*", $TT)

my $TT_digest = sha256( $TT );
### TT_digest: unpack("H*", $TT_digest)
my ( $Ka, $Ke ) = split_key( $TT_digest );
### Ka: unpack("H*", $Ka)
### Ke: unpack("H*", $Ke)

my $hash_name = 'SHA256';
my $hash_len  = 32;
my $aad       = '';
my $Kc        = hkdf( $Ka, '', $hash_name, $hash_len, "ConfirmationKeys" || $aad );
my ( $KcA, $KcB ) = split_key( $Kc );
### KcA: unpack("H*", $KcA)
### KcB: unpack("H*", $KcB)

my $MacA = hmac_sha256( $Y, $KcA );
### MacA: unpack("H*", $MacA)
my $MacB = hmac_sha256( $X, $KcB );
### MacB: unpack("H*", $MacB)

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

  my $curve = Crypt::Perl::ECDSA::EC::Curve->new( @{$curve_hr}{ 'p', 'a', 'b' } );
  my $biX   = $point->get_x()->to_bigint();
  my $biY   = $point->get_y()->to_bigint();

  my $key_hex_len = 2 * Crypt::Perl::Math::ceil( $curve->keylen() / 8 );

  my ( $hx, $hy ) = map { substr( $_->as_hex(), 2 ) } $biX, $biY;
  $_ = sprintf "%0${key_hex_len}s", $_ for ( $hx, $hy );

  my $s = pack( "H*", join( '', '04', $hx, $hy ) );
  return $s;
}

sub split_key {
  my ( $k ) = @_;
  return unless ( defined $k );

  my $len = length( $k );
  my $ka  = substr $k, 0, $len / 2;
  my $kb  = substr $k, $len / 2;

  return ( $ka, $kb );
}
