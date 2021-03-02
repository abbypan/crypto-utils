#!/usr/bin/perl

use Crypt::KeyDerivation ':all';

#$ perl hkdf.pl a27e195cf3ea9755eceb1f77ca0dd20ba1fdaa8832f1b2fb637c8912ad3dce13 dc4dab0be272e8e85afb0aa1d423813bf9a5a2c31d14dd231992aabb4f6fc6f0 somelabel 32 SHA256
#f1bf30afd3f7c964a750244ff2e1daed8ad130fe12ff2cb844bd9d556c10e39e

my ($password, $salt, $info, $len, $hash_name) = @ARGV;
#hash name:SHA256 

$password = pack("H*", $password);
$salt = pack("H*",$salt);

$okm2 = hkdf($password, $salt, $hash_name, $len, $info);

printf("%s\n", unpack("H*", $okm2));
