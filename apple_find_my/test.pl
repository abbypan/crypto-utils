#!/usr/bin/perl

my ($i) = @ARGV;
system(qq[openssl ec -text -in d_${i}_private.pem]);
system(qq[openssl ec -text -pubin -in P_${i}_public.pem]);
