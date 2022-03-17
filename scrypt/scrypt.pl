#!/bin/bash
use Crypt::Scrypt;

 
my $scrypt = Crypt::Scrypt->new(
    key          => '123456',
    max_mem      => $bytes,
    max_mem_frac => $fraction,
    max_time     => $seconds
);
my $ciphertext = $scrypt->encrypt($plaintext);
