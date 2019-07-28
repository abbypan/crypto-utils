#!/usr/bin/python
# ECC + AES hybrid encryption
# see also: https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption.html

from tinyec import registry
from Cryptodome.Cipher import AES
import secrets, binascii

curve = registry.get_curve('secp256r1')

alice_privKey = secrets.randbelow(curve.field.n)
alice_pubKey = alice_privKey * curve.g

bob_privKey = secrets.randbelow(curve.field.n)
bob_pubKey = bob_privKey * curve.g

msg = b'fortest'
print("\noriginal msg: " + str(msg) + "\n")

# alice encrypt msg
alice_ecdh_key = alice_privKey * bob_pubKey 
alice_gcm_key = (hex(alice_ecdh_key.x))[2:34]
alice_gcm_iv = (hex(alice_ecdh_key.y))[2:26]
print("alice ecdh key: " + hex(alice_ecdh_key.x) +  " , "  + hex(alice_ecdh_key.y))
print("alice gcm key: " + alice_gcm_key  + " , alice gcm iv: " + alice_gcm_iv)
aesCipher = AES.new(binascii.unhexlify(alice_gcm_key), AES.MODE_GCM, nonce = binascii.unhexlify(alice_gcm_iv))
ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
print("\nalice ciphertext: " + str(binascii.hexlify(ciphertext)))
print("alice authTag: " + str(binascii.hexlify(authTag)) + "\n")

# bob decrypt msg
bob_ecdh_key = bob_privKey * alice_pubKey 
bob_gcm_key = (hex(bob_ecdh_key.x))[2:34]
bob_gcm_iv = (hex(bob_ecdh_key.y))[2:26]
print("bob ecdh key: " + hex(bob_ecdh_key.x) +  " , "  + hex(bob_ecdh_key.y))
print("bob gcm key: " + bob_gcm_key  + " , bob gcm iv: " + bob_gcm_iv)
aesCipher = AES.new(binascii.unhexlify(bob_gcm_key), AES.MODE_GCM, nonce = binascii.unhexlify(bob_gcm_iv))
plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
print("\nbob decrypt plaintext: " + str(plaintext))
