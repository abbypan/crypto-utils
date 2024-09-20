#!/usr/bin/perl
use strict;
use warnings;

use File::Slurp qw/slurp write_file/;
use PBKDF2::Tiny qw/derive/;
use Crypt::CBC;
use Digest::SHA qw/hmac_sha256/;
use Crypt::OpenSSL::PKCS::Func qw/PKCS12_key_gen/;

my ( $p12, $password, $prf, $dk_len ) = @ARGV;
$prf    //= "SHA-256";
$dk_len //= 32;

parse_pkcs12( $p12, $password, $prf, $dk_len );

sub parse_pkcs12 {
  my ( $p12, $password, $prf, $dk_len ) = @_;
  my $c = slurp( $p12 );

  my ( $pfx ) = read_asn1_step( $c );
  my ( $pfx_version, $authSafe, $macData ) = read_asn1_step( $pfx );
  my ( $contentType, $AuthenticatedSafe ) = read_asn1_step( $authSafe );

  my ( $AuthenticatedSafeSeq ) = read_asn1_step( $AuthenticatedSafe );
  write_file( "$p12.authsafes_d_data.bin", { binmode => ":raw" }, $AuthenticatedSafeSeq );

  #mac {{
  my ( $mac, $mac_salt, $mac_iter ) = read_asn1_step( $macData );
  write_file( "$p12.mac_salt.bin", { binmode => ":raw" }, $mac_salt );
  write_file( "$p12.mac_iter.bin", { binmode => ":raw" }, $mac_iter );
  my ( $mac_dgst_algor, $mac_dgst ) = read_asn1_step( $mac );
  write_file( "$p12.mac_dgst.bin", { binmode => ":raw" }, $mac_dgst );

  #use password, salt, iter to calc mac_key with RFC7292 algorithm, openssl PKCS12_key_gen function
  my $md = lc( $prf );
  $md =~ s/-//;
  my $mac_key_hexstr =
    PKCS12_key_gen( $password, unpack( 'H*', $mac_salt ), 3, oct( '0x' . unpack( 'H*', $mac_iter ) ), $dk_len, $md );
  $mac_key_hexstr =~ s/://g;
  my $mac_key = pack( 'H*', $mac_key_hexstr );
  write_file( "$p12.mac_key.bin", { binmode => ":raw" }, $mac_key );

  my $calc_mac_dgst = hmac_sha256( $AuthenticatedSafeSeq, $mac_key );
  write_file( "$p12.calc_mac_dgst.bin", { binmode => ":raw" }, $calc_mac_dgst );

  #verify mac dgst
  return if ( $mac_dgst ne $calc_mac_dgst );

  #print unpack("H*", $calc_mac_dgst), "\n";
  #}}

  #cert and priv
  my ( $AuthenticatedSafeSeq2 ) = read_asn1_step( $AuthenticatedSafeSeq );
  my ( $cert_ContentInfo, $priv_ContentInfo ) = read_asn1_step( $AuthenticatedSafeSeq2 );

  ## cert {{
  my ( $cert_contentType, $cert_encryptedData ) = read_asn1_step( $cert_ContentInfo );
  my ( $cert_encryptedData2 ) = read_asn1_step( $cert_encryptedData );
  my ( $cert_encrypted_version, $cert_encryptedContentInfo ) = read_asn1_step( $cert_encryptedData2 );
  my ( $cert_contentType_name, $cert_contentEncryptionAlgorithm, $cert_encryptedContent ) =
    read_asn1_step( $cert_encryptedContentInfo );
  write_file( "$p12.cert_enc.bin", { binmode => ":raw" }, $cert_encryptedContent );

  my ( $cert_salt, $cert_iter, $cert_iv ) = read_pbes2_attr( $cert_contentEncryptionAlgorithm );
  write_file( "$p12.cert_salt.bin", { binmode => ":raw" }, $cert_salt );
  write_file( "$p12.cert_iter.bin", { binmode => ":raw" }, $cert_iter );
  write_file( "$p12.cert_iv.bin",   { binmode => ":raw" }, $cert_iv );
  my $cert_key = generate_dk( $prf, $password, $cert_salt, $cert_iter, $dk_len );
  write_file( "$p12.cert_key.bin", { binmode => ":raw" }, $cert_key );
  my $cert_plain = aes_cbc_decrypt( $cert_encryptedContent, $cert_key, $cert_iv );
  write_file( "$p12.cert_plain.bin", { binmode => ":raw" }, $cert_plain );

  my ( $cert_seq )  = read_asn1_step( $cert_plain );
  my ( $cert_seq2 ) = read_asn1_step( $cert_seq );
  my ( $cert_oid, $cert_context, $cert_keyid ) = read_asn1_step( $cert_seq2 );
  my ( $cert_context2 ) = read_asn1_step( $cert_context );
  my ( $cert_oid2, $cert_data ) = read_asn1_step( $cert_context2 );
  my ( $cert_final ) = read_asn1_step( $cert_data );
  write_file( "$p12.cert_final.bin", { binmode => ":raw" }, $cert_final );

  #system(qq[openssl x509 -text -in $p12.cert_final.bin -inform der]);
  #}}

  ## priv key {{
  my ( $priv_contentType, $priv_safeContents ) = read_asn1_step( $priv_ContentInfo );
  my ( $priv_bags ) = read_asn1_step( $priv_safeContents );
  my ( $priv_bag )  = read_asn1_step( $priv_bags );
  my ( $priv_bag2 ) = read_asn1_step( $priv_bag );
  my ( $bag_id, $PKCS8ShroudedKeyBag, $bag_attr ) = read_asn1_step( $priv_bag2 );
  my ( $PKCS8ShroudedKeyBag2 ) = read_asn1_step( $PKCS8ShroudedKeyBag );
  my ( $priv_contentEncryptionAlgorithm, $priv_encryptedData ) = read_asn1_step( $PKCS8ShroudedKeyBag2 );
  write_file( "$p12.priv_enc.bin", { binmode => ":raw" }, $priv_encryptedData );

  my ( $priv_salt, $priv_iter, $priv_iv ) = read_pbes2_attr( $priv_contentEncryptionAlgorithm );
  write_file( "$p12.priv_salt.bin", { binmode => ":raw" }, $priv_salt );
  write_file( "$p12.priv_iter.bin", { binmode => ":raw" }, $priv_iter );
  write_file( "$p12.priv_iv.bin",   { binmode => ":raw" }, $priv_iv );
  my $priv_key = generate_dk( $prf, $password, $priv_salt, $priv_iter, $dk_len );
  write_file( "$p12.priv_key.bin", { binmode => ":raw" }, $priv_key );
  my $priv_plain = aes_cbc_decrypt( $priv_encryptedData, $priv_key, $priv_iv );
  write_file( "$p12.priv_plain.bin", { binmode => ":raw" }, $priv_plain );

  my ( $priv_data ) = read_asn1_step( $priv_plain );
  my ( $priv_int, $priv_seq, $priv_data2 ) = read_asn1_step( $priv_data );
  my ( $priv_data3 ) = read_asn1_step( $priv_data2 );
  my ( $priv_v, $priv_final ) = read_asn1_step( $priv_data3 );
  write_file( "$p12.priv_final.bin", { binmode => ":raw" }, $priv_final );

  #system(qq[xxd $p12.priv_final.bin]);
  ## }}

  return ( $cert_final, $priv_final );
} ## end sub parse_pkcs12

sub aes_cbc_decrypt {
  my ( $cipher_text, $key, $iv ) = @_;
  my $cbc = Crypt::CBC->new(
    -cipher      => "Cipher::AES",
    -key         => $key,
    -iv          => $iv,
    -cipher      => "OpenSSL::AES",
    -literal_key => 1,
    -header      => "none",

    #-keysize=>$dk_len,
  );
  my $plain_text = $cbc->decrypt( $cipher_text );
  return $plain_text;
}

sub generate_dk {
  my ( $prf, $pass, $salt, $iter, $dk_len ) = @_;
  my $iter_n = oct( "0x" . unpack( "H*", $iter ) );
  my $dk = derive( $prf, $pass, $salt, $iter_n, $dk_len );
  return $dk;
}

sub read_pbes2_attr {
  my ( $c ) = @_;
  my ( $algorithm_id, $params )           = read_asn1_step( $c );
  my ( $pbkdf2,       $encryptionScheme ) = read_asn1_step( $params );

  my ( $pbkdf2_id, $pbkdf2_params ) = read_asn1_step( $pbkdf2 );
  my ( $salt, $iter, $prf ) = read_asn1_step( $pbkdf2_params );

  my ( $encrypt_id, $aes_iv ) = read_asn1_step( $encryptionScheme );
  return ( $salt, $iter, $aes_iv );
}

sub read_asn1_step {
  my ( $c ) = @_;

  my @res;

  while ( $c ) {
    my ( $tag, $length, $remain ) = ( $c ) =~ m#^(.)(.)(.+)#s;
    my $flag = $length & pack( "H*", "80" );
    my $data;
    my $octet;
    if ( unpack( "H*", $flag ) eq "80" ) {
      my $length_len = $length & pack( "B*", "01111111" );
      my $n = oct( "0b" . unpack( "B*", $length_len ) );
      my $len = oct( "0x" . unpack( "H*", substr( $remain, 0, $n ) ) );
      $data  = substr( $remain, $n, $len );
      $octet = substr( $c,      0,  2 + $n + $len );
      $remain = substr( $remain, $n + $len );
    } else {
      my $len = oct( "0x" . unpack( "H*", $length ) );
      $data  = substr( $remain, 0, $len );
      $octet = substr( $c,      0, 2 + 1 + $len );
      $remain = substr( $remain, $len );
    }

    #push @res, { tag => $tag, data => $data, octet => $octet };
    push @res, $data;
    $c = $remain;
  } ## end while ( $c )
  return @res;
} ## end sub read_asn1_step
