#!/usr/bin/perl

use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use File::Slurp qw/slurp/;

my ($key, $iv, $aad, $plain_f) = @ARGV;
$key = pack("H*", $key);
$iv = pack("H*", $iv);
#$aad =undef;

my $cipher = 'AES';
my $plaintext = slurp($plain_f);
print "plaintext:\n".unpack("H*", $plaintext). "\n";

my ($ciphertext, $tag) = gcm_encrypt_authenticate($cipher, $key, $iv, $aad, $plaintext);

print "ciphertext:\n".unpack("H*", $ciphertext). "\n";
print "tag:\n".unpack("H*", $tag). "\n";

my $dec = gcm_decrypt_verify($cipher, $key, $iv, $aad, $ciphertext, $tag);
print "dec:\n".unpack("H*", $dec). "\n";
