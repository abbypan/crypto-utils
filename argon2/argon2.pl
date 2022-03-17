#!/usr/bin/perl

use Crypt::Argon2 qw/argon2id_pass argon2id_verify/;

#argon2id_pass($password, $salt, $t_cost, $m_factor, $parallelism, $tag_size)
my $password = 'Hello World';
my $salt = pack("H*", '1ef530f2b6307010b362fa33c01fd278104e88bf1e256cde38780380dfc52f42');
my $encoded = argon2id_pass($password, $salt, 4, '32M', 3, 32);
print $encoded, "\n";
