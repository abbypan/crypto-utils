#!/usr/bin/perl
use strict;
use warnings;

use Crypt::RSA::DataFormat qw(octet_len os2ip i2osp octet_xor);
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;
use Data::Dumper;

use Digest::SHA qw/sha256/;

our $HSUB = \&sha256;
our $HLEN = 32;
our $SLEN = $HLEN;

my ( $n, $e, $signature, $m, $is_mhash ) = @ARGV;
my $mhash = $is_mhash ? $m : calc_mhash( $m );

my $v = rsassa_pss_verify_mhash( $n, $e, $signature, $mhash );
print "Verify Result: $v\n";

sub rsassa_pss_verify_mhash {
    my ( $n, $e, $signature, $mhash ) = @_;

    print "n: $n\n";
    $n       = Crypt::OpenSSL::Bignum->new_from_hex( $n );
    my $modBits = $n->num_bits;
    print "modBits: $modBits\n";

    print "e: $e\n";
    $e = Crypt::OpenSSL::Bignum->new_from_hex( $e );

    my $rsa_pub = Crypt::OpenSSL::RSA->new_key_from_parameters(
        $n,
        $e,
    );
    $rsa_pub->use_no_padding();

    print "signature: $signature\n";
    $signature = pack( "H*", $signature );

    my $em = $rsa_pub->public_decrypt( $signature );
    $em = unpack( "H*", $em );
    my $em_n   = Crypt::OpenSSL::Bignum->new_from_hex( $em );
    my $emBits = $em_n->num_bits;
    print "em: $em\n";
    print "emBits: $emBits\n";

    my $v = emsa_pss_verify_mhash( $mhash, $em, $modBits - 1 );

    return $v;
} ## end sub rsassa_pss_verify_mhash

sub calc_mhash {
    my ( $m ) = @_;
    return unpack( "H*", $HSUB->( pack( "H*", $m ) ) );
}

sub emsa_pss_verify_mhash {
    my ( $mhash, $em, $emBits ) = @_;

    print "mHash: $mhash\n";

    my $emLen = length( $em ) / 2;
    return 0 if ( $emLen < $HLEN + $SLEN + 2 );

    my ( $em_tail ) = $em =~ m#(..)$#;
    return 0 if ( $em_tail ne 'bc' );

    my $maskedDB = substr $em, 0, ( ( $emLen - $HLEN - 1 ) * 2 );
    print "maskedDB: $maskedDB\n";

    my $H = substr $em, ( $emLen - $HLEN - 1 ) * 2, $HLEN * 2;
    print "H: $H\n";

    my $left_most_octet_masked_DB = unpack( "B*", pack( "H*", substr $maskedDB, 0, 2 ) );
    my $left_most_bits            = 8 * $emLen - $emBits;
    if ( $left_most_bits > 0 ) {
        my $left_most_bits_cut = substr $left_most_octet_masked_DB, 0, $left_most_bits;
        return 0 if ( $left_most_bits_cut !~ /^0+$/ );
    }

    my $dbMask = mgf( pack( "H*", $H ), $emLen - $HLEN - 1 );
    print "dbMask: ", unpack( "H*", $dbMask ), "\n";

    my $DB = octet_xor( pack( "H*", $maskedDB ), $dbMask );
    if ( $left_most_bits > 0 ) {
        my $DB_BIN = unpack( "B*", $DB );
        substr( $DB_BIN, 0, $left_most_bits ) = ( "0" ) x $left_most_bits;
        $DB = pack( "B*", $DB_BIN );
    }
    $DB = unpack( "H*", $DB );
    print "DB: $DB\n";

    my $DB_zero = substr( $DB, 0, ( $emLen - $HLEN - $SLEN - 2 ) * 2 );
    return 0 if ( $DB_zero !~ /^0*$/ );

    my $DB_one = substr( $DB, ( $emLen - $HLEN - $SLEN - 2 ) * 2, 2 );
    return 0 if ( $DB_one !~ /^01$/ );

    my $salt = substr( $DB, ( $emLen - $HLEN - $SLEN - 1 ) * 2, $SLEN * 2 );
    print "salt: $salt\n";

    my $M_ = ( "00" ) x 8;
    $M_ .= $mhash . $salt;
    print "M': $M_\n";

    my $H_ = $HSUB->( pack( "H*", $M_ ) );
    $H_ = unpack( "H*", $H_ );
    print "H': $H_\n";

    return ( $H_ eq $H ) ? 1 : 0;
} ## end sub emsa_pss_verify_mhash

sub mgf {
    my ( $seed, $l ) = @_;
    my $imax = int( ( $l + $HLEN - 1 ) / $HLEN ) - 1;
    my $T    = "";
    foreach my $i ( 0 .. $imax ) {
        $T .= $HSUB->( $seed . i2osp( $i, 4 ) );
    }
    my ( $output ) = unpack "a$l", $T;
    return $output;
}
