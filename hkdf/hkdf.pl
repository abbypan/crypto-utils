#!/usr/bin/perl

use Crypt::KeyDerivation ':all';

my ($password_hexstr, $salt_hexstr, $info, $byte_len, $hash_name) = @ARGV;

my $password = pack("H*", $password_hexstr);
my $salt = pack("H*",$salt_hexstr);

my $okm = hkdf($password, $salt, $hash_name, $byte_len, $info);

my $okm_hexstr = unpack("H*", $okm);
printf("%s\n", $okm_hexstr);
