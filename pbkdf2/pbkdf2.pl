#/usr/bin/perl

use PBKDF2::Tiny qw/derive verify/;
 
my $pass = '123456';
my $salt = pack('H*', 'b698314b0d68bcbd');
my $iters = 2048;

my $dk_len = 32;
my $dk = derive( 'SHA-256', $pass, $salt, $iters, $dk_len );

print unpack('H*', $dk), "\n";
#f68b5386de3a8d6335846950544d29a55ad3328dea17685304d7822848aec534
