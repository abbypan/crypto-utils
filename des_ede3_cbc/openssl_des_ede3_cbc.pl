#!/usr/bin/perl
#see also: https://www.iit.comillas.edu/palacios/seguridad/openssl.pdf

use strict;
use warnings;
use File::Slurp qw/slurp write_file/;

my $alg = 'des-ede3-cbc';

my $src = 'justfortest';
my $pwd = 'testpwd';

my $iter = 2048;
my $md = 'sha1';
my $salt = 'A1A2A3A4A5A6A7A8'; #8 byte

print "\nencrypt:\n";
print "src:$src\n";
my $src_f = "$alg.src.txt";
write_file($src_f, $src);

my $enc_f = "$alg.enc";
my $para_f = "$alg.para";
system(qq[openssl enc -$alg -in $src_f -k $pwd -iter $iter -md $md -S $salt -out $enc_f -p | tee $para_f]);

print "\n\ndecrypt $enc_f:\n";
my $decrypt_enc_f = "$alg.decrypt-enc.txt";
system(qq[openssl enc -d -$alg -in $enc_f -k $pwd -iter $iter -md $md -S $salt -out $decrypt_enc_f -p]);
print "decrypt enc:".slurp($decrypt_enc_f)."\n";

print "\n\nread_para:\n";
my $para = slurp($para_f);
my ($KEY) = $para=~m#key=(\N+)#s;
my ($IV) = $para=~m#iv\s*=(\N+)#s;
print "KEY=$KEY\nIV=$IV\n";

print "\n\nread $enc_f:\n";
my $cihper_text = unpack('H*', slurp($enc_f));
my ($head, $S, $cipher_content) = $cihper_text=~m#^(.{16})(.{16})(.+)$#s;
print "head=$head\nsalt=$S\ncipher_content=$cipher_content\n";
my $cipher_f = "$alg.cipher";
write_file($cipher_f, {binmode => ':raw' }, pack('H*', $cipher_content));

print "\n\ndecrypt $cipher_f:\n";
my $decrypt_cipher_f = "$alg.decrypt-cipher.txt";
system(qq[openssl enc -d -$alg -in $cipher_f -K $KEY -iv $IV -out $decrypt_cipher_f]);
print "decrypt cipher:".slurp($decrypt_cipher_f)."\n";
