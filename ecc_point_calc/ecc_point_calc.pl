#!/usr/bin/perl
#http://cacr.uwaterloo.ca/techreports/1999/corr99-34.pdf

use strict;
use warnings;

use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum::CTX;
use Data::Dumper;

# y^2 = x^3 + x + 4
my ( $p, $a, $b ) = map { Crypt::OpenSSL::Bignum->new_from_decimal( $_ ) } ( 23, 1, 4 );
print "p: ", $p->to_decimal(), ", a: ", $a->to_decimal(), ", b: ", $b->to_decimal(), "\n\n";

my $ctx    = Crypt::OpenSSL::Bignum::CTX->new();
my $method = Crypt::OpenSSL::EC::EC_GFp_mont_method();
my $group  = Crypt::OpenSSL::EC::EC_GROUP::new( $method );
$group->set_curve_GFp( $p, $a, $b, $ctx );

##P1
my $P1 = Crypt::OpenSSL::EC::EC_POINT::new( $group );
my ( $x1, $y1 ) = map { Crypt::OpenSSL::Bignum->new_from_decimal( $_ ) } ( 0, 2 );
Crypt::OpenSSL::EC::EC_POINT::set_affine_coordinates_GFp( $group, $P1, $x1, $y1, $ctx );

#my $is_P1_on_the_curve = Crypt::OpenSSL::EC::EC_POINT::is_on_curve($group, $P1, $ctx);
#print Dumper($is_P1_on_the_curve);
print "P1: ";
parse_ec_point( $group, $P1, $ctx );

##P2
my $P2 = Crypt::OpenSSL::EC::EC_POINT::new( $group );
my ( $x2, $y2 ) = map { Crypt::OpenSSL::Bignum->new_from_decimal( $_ ) } ( 4, 7 );
Crypt::OpenSSL::EC::EC_POINT::set_affine_coordinates_GFp( $group, $P2, $x2, $y2, $ctx );
print "P2: ";
parse_ec_point( $group, $P2, $ctx );

##Q=P1 + P2
my $Q = Crypt::OpenSSL::EC::EC_POINT::new( $group );
Crypt::OpenSSL::EC::EC_POINT::add( $group, $Q, $P1, $P2, $ctx );
print "P1+P2: ";
my ( $x, $y, $buf_s ) = parse_ec_point( $group, $Q, $ctx );

my $y2_sub_y1 = mod_sub( $y2, $y1, $p, $ctx );
my $x2_sub_x1 = mod_sub( $x2, $x1, $p, $ctx );
my $y_div_x   = mod_div( $y2_sub_y1, $x2_sub_x1, $p, $ctx );
my $yy_div_xx = mod_exp( $y_div_x, Crypt::OpenSSL::Bignum->new_from_decimal( 2 ), $p, $ctx );
my $res1      = mod_sub( $yy_div_xx, $x1, $p, $ctx );
my $x3        = mod_sub( $res1, $x2, $p, $ctx );
print $x3->to_decimal(), "\n";
my $x1_sub_x3 = mod_sub( $x1, $x3, $p, $ctx );
my $res2      = mod_mul( $y_div_x, $x1_sub_x3, $p, $ctx );
my $y3        = mod_sub( $res2, $y1, $p, $ctx );
print $y3->to_decimal(), "\n\n";

## R = 2*P1
my $R = Crypt::OpenSSL::EC::EC_POINT::new( $group );
Crypt::OpenSSL::EC::EC_POINT::add( $group, $R, $P1, $P1, $ctx );
print "2*P1: ";
my ( $xr, $yr, $buf_sr ) = parse_ec_point( $group, $R, $ctx );

my $xx1             = mod_exp( $x1, Crypt::OpenSSL::Bignum->new_from_decimal( 2 ), $p, $ctx );
my $xx1_mul_3       = mod_mul( $xx1, Crypt::OpenSSL::Bignum->new_from_decimal( 3 ), $p, $ctx );
my $xx1_mul_3_add_a = mod_add( $xx1_mul_3, $a, $p, $ctx );
my $y1_mul_2        = mod_mul( $y1, Crypt::OpenSSL::Bignum->new_from_decimal( 2 ), $p, $ctx );
my $res3            = mod_div( $xx1_mul_3_add_a, $y1_mul_2, $p, $ctx );
my $res2_exp_2      = mod_exp( $res3, Crypt::OpenSSL::Bignum->new_from_decimal( 2 ), $p, $ctx );
my $x1_mul_2        = mod_mul( $x1, Crypt::OpenSSL::Bignum->new_from_decimal( 2 ), $p, $ctx );
my $x4              = mod_sub( $res2_exp_2, $x1_mul_2, $p, $ctx );
print $x4->to_decimal(), "\n";
my $x1_sub_x4 = mod_sub( $x1, $x4, $p, $ctx );
my $res4      = mod_mul( $res3, $x1_sub_x4, $p, $ctx );
my $y4        = mod_sub( $res4, $y1, $p, $ctx );
print $y4->to_decimal(), "\n\n";

sub parse_ec_point {
  my ( $group, $Q, $ctx ) = @_;
  my $buf = Crypt::OpenSSL::EC::EC_POINT::point2oct( $group, $Q, &Crypt::OpenSSL::EC::POINT_CONVERSION_UNCOMPRESSED, $ctx );
  my $x   = Crypt::OpenSSL::Bignum->new();
  my $y   = Crypt::OpenSSL::Bignum->new();
  Crypt::OpenSSL::EC::EC_POINT::get_affine_coordinates_GFp( $group, $Q, $x, $y, $ctx );
  my $buf_s = unpack( "H*", $buf );
  print "oct: ", $buf_s, ", x: ", $x->to_decimal(), ", y: ", $y->to_decimal(), "\n\n";
  return ( $x, $y, $buf_s );
}

sub mod_exp {
  my ( $x, $e, $modulus, $ctx ) = @_;
  return $x->mod_exp( $e, $modulus, $ctx );
}

sub mod_mul {
  my ( $y, $x, $modulus, $ctx ) = @_;
  my $ry = $y->mod( $modulus, $ctx );
  my $rx = $x->mod( $modulus, $ctx );
  return $ry->mod_mul( $rx, $modulus, $ctx );
}

sub mod_div {
  my ( $y, $x, $modulus, $ctx ) = @_;
  my $x_reverse = $x->mod_inverse( $modulus, $ctx );
  return mod_mul( $y, $x_reverse, $modulus, $ctx );
}

sub mod_add {
  my ( $y, $x, $modulus, $ctx ) = @_;
  my $ry = $y->mod( $modulus, $ctx );
  my $rx = $x->mod( $modulus, $ctx );
  my $c  = $ry->add( $rx );
  return $c->mod( $modulus, $ctx );
}

sub mod_sub {
  my ( $y, $x, $modulus, $ctx ) = @_;
  my $ry = $y->mod( $modulus, $ctx );
  my $rx = $x->mod( $modulus, $ctx );
  my $c  = $ry->sub( $rx );
  return $c->mod( $modulus, $ctx );
}
