/*************************************************************************
 * Written in 2020-2022 by Elichai Turkel                                *
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <sys/random.h>

static void print_hex(unsigned char* data, size_t size) {
    size_t i;
    printf("0x");
    for (i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    unsigned char msg[] = "justfortest";
    unsigned char tag[] = "some_protocol";
    unsigned char msg_hash[32];

    unsigned char seckey[32];
    unsigned char randomize[32];
    unsigned char auxiliary_rand[32];
    unsigned char serialized_pubkey[32];
    unsigned char signature[64];
    int is_signature_valid, is_signature_valid2;
    int return_val;

    secp256k1_xonly_pubkey pubkey;
    secp256k1_keypair keypair;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    ssize_t res = getrandom(randomize, sizeof(randomize), 0);
    if (res<0 || (size_t) res != sizeof(randomize)) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    return_val = secp256k1_context_randomize(ctx, randomize);

    res = getrandom(seckey, sizeof(seckey), 0);
    if (res<0 || (size_t) res != sizeof(seckey)) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    return_val = secp256k1_keypair_create(ctx, &keypair, seckey);

    return_val = secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair);

    return_val = secp256k1_xonly_pubkey_serialize(ctx, serialized_pubkey, &pubkey);
    if(return_val!=1){
        printf("Not valid public key\n");
        return 1;
    }

    return_val = secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof(tag), msg, sizeof(msg));

    res = getrandom(auxiliary_rand, sizeof(auxiliary_rand), 0);
    if (res<0 || (size_t) res != sizeof(auxiliary_rand)) {
        printf("Failed to generate randomness\n");
        return 1;
    }

    return_val = secp256k1_schnorrsig_sign32(ctx, signature, msg_hash, &keypair, auxiliary_rand);

    if (!secp256k1_xonly_pubkey_parse(ctx, &pubkey, serialized_pubkey)) {
        printf("Failed parsing the public key\n");
        return 1;
    }

    return_val = secp256k1_tagged_sha256(ctx, msg_hash, tag, sizeof(tag), msg, sizeof(msg));

    is_signature_valid = secp256k1_schnorrsig_verify(ctx, signature, msg_hash, 32, &pubkey);

    printf("Secret Key: ");
    print_hex(seckey, sizeof(seckey));
    printf("Public Key: ");
    print_hex(serialized_pubkey, sizeof(serialized_pubkey));
    printf("Signature: ");
    print_hex(signature, sizeof(signature));
    printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");

    secp256k1_context_destroy(ctx);

    //only verify
    is_signature_valid2 = secp256k1_schnorrsig_verify(secp256k1_context_static, signature, msg_hash, 32, &pubkey);
    assert(is_signature_valid2 == is_signature_valid);

    memset(seckey, 0, sizeof(seckey));
    return 0;
}
