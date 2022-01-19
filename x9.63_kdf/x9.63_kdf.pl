#!/usr/bin/perl

use Digest;
use Data::Dumper;


#hash_name : SHA-256
my ($z, $shared_info, $key_data_len, $hash_name) = @ARGV;

my $k = x963_kdf($z, $shared_info, $key_data_len, $hash_name);
print unpack("H*", $k), "\n";

sub x963_kdf {
    my ($z, $shared_info, $key_data_len, $hash_name) = @_;

    my $counter = 1;
    my $k = '';
    my $current_len = 0;

    while($key_data_len>0){
        my $dgst = Digest->new($hash_name);

        my $c4 = pack 'L>', $counter;

        $dgst->add($z.$c4.$shared_info);
my $d = $dgst->digest();
        my $dlen = length($d);

        if($dlen <= $key_data_len){
            $k.=$d;
            $key_data_len-=$dlen;
        }else{
            $k.=substr($d, 0, $key_data_len);
            $key_data_len = 0;
        }
        $counter++;
    }
    return $k;
}
