#/usr/bin/perl

use PBKDF2::Tiny qw/derive verify/;

my ($pass, $salt_hexstr, $iters, $dk_len, $hash_name) = @ARGV;

my $salt = pack('H*', $salt_hexstr);

my $dk = derive( $hash_name, $pass, $salt, $iters, $dk_len );

my $dk_hexstr = unpack('H*', $dk);
print "password: $pass\nsalt_hexstr: $salt_hexstr\niter: $iters\ndk_len: $dk_len\nhash: $hash_name\ndk: $dk_hexstr\n";
