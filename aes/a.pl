#!/usr/bin/perl

#> echo -n 'ustc328ustc328ustc328xxxxxxxx' | ./aes256gcm 9bb6f934448315173ec3cb2ba3f2c5c709c56f4ca3da3bda2f7f844ce17db26d fbf0a086180eb5f3e525aa96 |xxd -p
#d50bc4fe3e1096b84a2b2a57ee9d3604ddb7a46d3c82d34183e42f3f2405927adb39a2be9db362d3efbdc73065

#> echo -n 'plain textyyyyyyyyyyyyyyyyyyy' | ./aes256gcm 9bb6f934448315173ec3cb2ba3f2c5c709c56f4ca3da3bda2f7f844ce17db26d fbf0a086180eb5f3e525aa96 |xxd -p
#d014d1f46302daa8412b301da5dc3a0ed0adee267d83d24082e52e3e25c1af8e8b1d2aa95ebac30ddbf45c78af
#
#/home/panll/Dropbox/github/crypto_sample/aes> echo -n 'ustc328ustc328ustc328xxxxxxxxqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq' | ./aes256gcm 9bb6f934448315173ec3cb2ba3f2c5c709c56f4ca3da3bda2f7f844ce17db26d fbf0a086180eb5f3e525aa96 |xxd -p
#d50bc4fe3e1096b84a2b2a57ee9d3604ddb7a46d3c82d34183e42f3f248125a31bd6b4f20a3e8f4828b3edd6848565c083125d43f55a5b43c01f868e10f33f258be3a778cab74ba0df896bd8494df8fe43899b4858d6b9b00f
#/home/panll/Dropbox/github/crypto_sample/aes> echo -n 'plain textyyyyyyyyyyyyyyyyyyyvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv' | ./aes256gcm 9bb6f934448315173ec3cb2ba3f2c5c709c56f4ca3da3bda2f7f844ce17db26d fbf0a086180eb5f3e525aa96 |xxd -p 
#d014d1f46302daa8412b301da5dc3a0ed0adee267d83d24082e52e3e258622a41cd1b3f50d39884f2fb4ead1838262c784155a44f25d5c44c718818917f438228ce4a07fcdb04ca7d8c6dac95cc3846767937f35c5e6a509a0


my $plain_a = 'ustc328ustc328ustc328xxxxxxxxqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq';
my $a =pack("H*", 'd50bc4fe3e1096b84a2b2a57ee9d3604ddb7a46d3c82d34183e42f3f248125a31bd6b4f20a3e8f4828b3edd6848565c083125d43f55a5b43c01f868e10f33f258be3a778cab74ba0df896bd8494df8fe43899b4858d6b9b00f');

my $plain_b = 'plain textyyyyyyyyyyyyyyyyyyyvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv';
my $b = pack("H*", 'd014d1f46302daa8412b301da5dc3a0ed0adee267d83d24082e52e3e258622a41cd1b3f50d39884f2fb4ead1838262c784155a44f25d5c44c718818917f438228ce4a07fcdb04ca7d8c6dac95cc3846767937f35c5e6a509a0');



my $e = $plain_a ^ $a ^ $b;
print $e, "\n";

my $e2 = $plain_b ^ $b ^ $a;
print $e2, "\n";
