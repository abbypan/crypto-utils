#!/usr/bin/perl

use Digest::SHA qw/hmac_sha256/;

#$ perl hmac.pl a27e195cf3ea9755eceb1f77ca0dd20ba1fdaa8832f1b2fb637c8912ad3dce13 dc4dab0be272e8e85afb0aa1d423813bf9a5a2c31d14dd231992aabb4f6fc6f0
#b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad

my ($key, $data) = @ARGV;
#hash name:SHA256 

$key = pack("H*", $key);
$data = pack("H*", $data);

my $mac = hmac_sha256($data, $key);

printf("%s\n", unpack("H*", $mac));
