#!/usr/bin/perl

use Digest::SHA qw/hmac_sha256/;

my ($key_hexstr, $data_hexstr) = @ARGV;

$key_bin = pack("H*", $key_hexstr);
$data_bin = pack("H*", $data_hexstr);

my $mac_bin = hmac_sha256($data_bin, $key_bin);
my $mac_hexstr = unpack("H*", $mac_bin);

printf("key_hexstr: %s\ndata_hexstr: %s\nhmac-sha256_hexstr: %s\n", $key_hexstr, $data_hexstr, $mac_hexstr);
