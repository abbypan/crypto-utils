#!/usr/bin/perl
use Digest::SHA qw/sha256/;
use List::Util qw/min/;

my %H_info = (
  'SHA256' => {
    'func'       => \&sha256,
    'b_in_bytes' => 32,
    'r_in_bytes' => 64,
  } );

#my $u=pack("H*", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f");
#my $prelen = prepend_len($u);
#print unpack("H*", $prelen), "\n";

#my $precat = prefix_free_cat("1234", "5", "", "6789");
#print unpack("H*", $precat), "\n";

#my $res = generator_string(
#'CPaceP256_XMD:SHA-256_SSWU_NU_',
#'Password',
#pack("H*", "0a41696e69746961746f720a42726573706f6e646572"),
#pack("H*", '34b36454cab2e7842c389f7d88ecb7df'),
#64);
#print unpack("H*", $res), "\n";

#my $res = calculate_generator(
#'CPaceP256_XMD:SHA-256_SSWU_NU_',
#'Password',
#pack("H*", "0a41696e69746961746f720a42726573706f6e646572"),
#pack("H*", '34b36454cab2e7842c389f7d88ecb7df'),
#'SHA256');
#my $res_hex = unpack("H*", $res), "\n";
#system(qq[perl hash_to_field.pl $res_hex 1 QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_]);
#system(qq[perl hash_to_field.pl $res_hex 1 CPaceP256_XMD:SHA-256_SSWU_NU_]);

#my $i;
#$i = lexiographically_larger("\0", "\0\0");
#print "lexiographically_larger: $i,\n";
#$i = lexiographically_larger("\1", "\0\0");
#print "lexiographically_larger: $i,\n";
#$i = lexiographically_larger( "\0\0","\0");
#print "lexiographically_larger: $i,\n";
#$i = lexiographically_larger( "\0\0","\1");
#print "lexiographically_larger: $i,\n";
#$i = lexiographically_larger( "\0\1","\1");
#print "lexiographically_larger: $i,\n";
#$i = lexiographically_larger( "ABCD","BCD");
#print "lexiographically_larger: $i,\n";

#my $s;
#$s = ocat("ABCD","BCD");
#print unpack("H*", $s), "\n";
#$s = ocat("BCD","ABCDE");
#print unpack("H*", $s), "\n";



my $ya = pack( "H*", "C9E47CA5DEBD2285727AF47E55F5B7763FA79719DA428F800190CC6659B4EAFB" );
my $Ya = pack(
  "H*",
  "0478AC925A6E3447A537627A2163BE005A422F55C08385C1EF7D051CA94593DF5946314120FAA87165CBA131C1DA3AAC429DC3D99A9BAC7D4C4CBB8570B4D5EA10"
);
my $ADa  = "ADa";
my $MSGa = prefix_free_cat( $Ya, $ADa );
print "msga: ", unpack( "H*", $MSGa ), "\n";

my $yb = pack( "H*", "A0B768BA7555621D133012D1DEE27A0013C1BCFDDD675811DF12771E44D77B10" );
my $Yb = pack(
  "H*",
  "04DF13FFA89B0CE3CC553B1495FF027886564D94B8D9165CD50E5F654247959951BFAC90839FCA218BF8E2D1258EB7D7D9F733FE4CD558E6FA57BF1F801AAE7D3A"
);
my $ADb  = "ADb";
my $MSGb = prefix_free_cat( $Yb, $ADb );
print "msgb: ", unpack( "H*", $MSGb ), "\n";

my $DSI = 'CPaceP256_XMD:SHA-256_SSWU_NU__ISK';
my $K=pack("H*", "27f7059d88f02007dc18c911c9b4034d3c0f13f8f7ed9603b0927f23fbab1037");
my $sid = pack("H*", "34b36454cab2e7842c389f7d88ecb7df");

my $unorder_trans = $MSGa.$MSGb;
my $unorder_Prepare_ISK = prefix_free_cat($DSI, $sid, $K).$unorder_trans;
print "prepare unorder isk: ", length($unorder_Prepare_ISK), "," , unpack("H*", $unorder_Prepare_ISK), "\n";
my $unorder_ISK = sha256($unorder_Prepare_ISK);
print "unorder isk: ", unpack("H*", $unorder_ISK), "\n";

my $order_trans = ocat($MSGa, $MSGb);
my $order_Prepare_ISK = prefix_free_cat($DSI, $sid, $K).$order_trans;
print "prepare order isk: ", length($order_Prepare_ISK), "," , unpack("H*", $order_Prepare_ISK), "\n";
my $order_ISK = sha256($order_Prepare_ISK);
print "order isk: ", unpack("H*", $order_ISK), "\n";


sub ocat {
  my ( $bytes1, $bytes2 ) = @_;
  return lexiographically_larger( $bytes1, $bytes2 ) ? $bytes1 . $bytes2 : $bytes2 . $bytes1;
}

sub lexiographically_larger {
  my ( $bytes1, $bytes2 ) = @_;
  my $min_len = min( length( $bytes1 ), length( $bytes2 ) );

  #print "bytes1: ", length($bytes1),",", unpack("B*", $bytes1), "\n";
  #print "bytes2: ", length($bytes2),",", unpack("B*", $bytes2), "\n";

  for my $m ( 0 .. $min_len - 1 ) {
    my $m1 = substr $bytes1, $m, 1;
    my $m2 = substr $bytes2, $m, 1;

    #print "m1: ", length($m1),",", unpack("B*", $m1), "\n";
    #print "m2: ", length($m2),",", unpack("B*", $m2), "\n";
    my $c = $m1 cmp $m2;

    #print "cmp m1 m2: $c\n";
    return 1 if ( $c > 0 );
    return 0 if ( $c < 0 );
  }
  my $larger = length( $bytes1 ) > length( $bytes2 ) ? 1 : 0;
  return $larger;
} ## end sub lexiographically_larger

sub calculate_generator {
  my ( $DSI, $PRS, $CI, $sid, $hash_name ) = @_;
  my $h_r     = $H_info{$hash_name};
  my $gen_str = generator_string( $DSI, $PRS, $CI, $sid, $h_r->{r_in_bytes} );
  return $gen_str;

  #my $gen_str_hash = $h_r->{func}->($gen_str);
  #return $gen_str_hash;
}

sub generator_string {
  my ( $DSI, $PRS, $CI, $sid, $s_in_bytes ) = @_;

  my $Z_pad = '';
  my $rn    = $s_in_bytes - 1 - length( prepend_len( $PRS ) ) - length( prepend_len( $DSI ) );
  $rn *= 2;
  $Z_pad = pack( "H$rn", '00' ) if ( $rn > 0 );

  my $res = prefix_free_cat( $DSI, $PRS, $Z_pad, $CI, $sid );
  return $res;
}

sub prefix_free_cat {
  my @data = @_;
  my $res  = join( "", map { prepend_len( $_ ) } @data );
  return $res;
}

sub prepend_len {
  my ( $data ) = @_;

  my $length_encoded = "";

  my $len = length( $data );
  do {
    if ( $len < 128 ) {
      $length_encoded .= pack( "C*", $len );
    } else {
      my $l = $len & 0x7f;
      $l += 0x80;
      $length_encoded .= pack( "C*", $l );
    }
    $len = int( $len >> 7 );

  } while ( $len > 0 );
  return $length_encoded . $data;
} ## end sub prepend_len
