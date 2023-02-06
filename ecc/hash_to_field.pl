#!/usr/bin/perl
#https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-10.html

use Digest::SHA qw(sha256);
use POSIX;
use bignum;
use Math::BigInt;

my %H_info = (
  'SHA256' => {
    'func'       => \&sha256,
    'b_in_bytes' => 32,
    'r_in_bytes' => 64,
  } );

#expand_message_xmd('abc', 'QUUX-V01-CS02-with-expander', 0x20, 'SHA256');
#expand_message_xmd('abc', 'QUUX-V01-CS02-with-expander', 0x80, 'SHA256');
#expand_message_xmd('abcdef0123456789', 'QUUX-V01-CS02-with-expander', 32, 'SHA256');
#expand_message_xmd( 'abcdef0123456789', 'QUUX-V01-CS02-with-expander', 0x80, 'SHA256' );
#expand_message_xmd('q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq', 'QUUX-V01-CS02-with-expander', 32, 'SHA256');

my $p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
#hash_to_field( 'abc', 2, 'QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_', $p, 1, 0x80, 'SHA256', \&expand_message_xmd );
my ($u, $cnt, $DST) = @ARGV;
#hash_to_field( $u, $cnt, $DST, $p, 1, 0x80, 'SHA256', \&expand_message_xmd );
#hash_to_field( $u, $cnt, $DST, $p, 1, 0x80, 'SHA256', \&expand_message_xmd );
$u = pack("H*", $u);
hash_to_field( $u, $cnt, $DST, $p, 1, 0x80, 'SHA256', \&expand_message_xmd );

sub hash_to_field {
  my ( $msg, $count, $DST, $p, $m, $k, $hash_name, $expand_message_func ) = @_;

  my $L             = ceil( ( ceil( log( $p ) / log( 2 ) ) + $k ) / 8 );
  print "L:$L\n";
  my $len_in_bytes  = $count * $m * $L;
  my $uniform_bytes = $expand_message_func->( $msg, $DST, $len_in_bytes, $hash_name );
  print "uniform_bytes: " . unpack( "H*", $uniform_bytes ) . "\n";

  my @res;
  for my $i ( 0 .. $count - 1 ) {
    my @u;
    for my $j ( 0 .. $m - 1 ) {
      my $elm_offset = $L * ( $j + $i * $m );
      my $tv         = substr( $uniform_bytes, $elm_offset, $L );
      my $tv_bn      = Math::BigInt->from_bytes( $tv );           # from hexadecimal
      $tv_bn->bmod( $p );
      my $e_j = $tv_bn->to_hex();
      push @u, $e_j;
      print "i=$i, j=$j, e_j=$e_j\n";
    }
    push @res, \@u;
  }
  return @res;
} ## end sub hash_to_field

sub expand_message_xmd {
  my ( $msg, $DST, $len_in_bytes, $hash_name ) = @_;

  my $h_r = $H_info{$hash_name};

  $ell = ceil( $len_in_bytes / $h_r->{b_in_bytes} );
  return if ( $ell > 255 );

  my $DST_len     = length( $DST );
  my $DST_len_hex = pack( "C*", $DST_len );
  my $DST_prime   = $DST . $DST_len_hex;
  print unpack( "H*", $DST_prime ), "\n";

  my $rn    = $h_r->{r_in_bytes} * 2;
  my $Z_pad = pack( "H$rn", '00' );
  print unpack( "H*", $Z_pad ), "\n";

  print $len_in_bytes, "\n";
  my $l_i_b_str = pack( "S>", $len_in_bytes );
  print unpack( "H*", $l_i_b_str ), "\n";

  my $zero = pack( "H*", '00' );

  my $msg_prime = $Z_pad . $msg . $l_i_b_str . $zero . $DST_prime;
  print unpack( "H*", $msg_prime ), "\n";

  my $len = pack( "C*", 1 );
  print unpack( "H*", $len ), "\n";
  my $b0 = $h_r->{func}->( $msg_prime );
  my $b1 = $h_r->{func}->( $b0 . $len . $DST_prime );

  my $b_prev        = $b1;
  my $uniform_bytes = $b1;
  for my $i ( 2 .. $ell ) {
    my $bi = $h_r->{func}->( ( $b0 ^ $b_prev ) . pack( "C*", $i ) . $DST_prime );
    $uniform_bytes .= $bi;
    $b_prev = $bi;
  }

  my $res = substr( $uniform_bytes, 0, $len_in_bytes );
  print unpack( "H*", $res ), "\n";
  return $res;
} ## end sub expand_message_xmd
