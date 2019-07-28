#!/usr/bin/python
# ECC + AES hybrid encryption
# see also: https://cryptobook.nakov.com/asymmetric-key-ciphers/ecc-encryption-decryption.html

from tinyec import registry
from Cryptodome.Cipher import AES
import hashlib, secrets, binascii

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_128_bit_key(point):
    sha = hashlib.sha256()
    sha.update(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    d = sha.digest()
    k = d[16:]
    return k


def encrypt_ECC(curve, msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    print("ciphertextPrivKey: " + hex(ciphertextPrivKey))
    print("pubKey: " + hex(pubKey.x) + ", " + hex(pubKey.y))
    print("sharedECCKey: " + hex(sharedECCKey.x) + ", " + hex(sharedECCKey.y))

    secretKey = ecc_point_to_128_bit_key(sharedECCKey)
    print("AES secretKey: " + binascii.hexlify(secretKey).decode('ascii'))

    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    print("privKey: " + hex(privKey))

    sharedECCKey = privKey * ciphertextPubKey
    print("sharedECCKey: " + hex(sharedECCKey.x) + ", " + hex(sharedECCKey.y))

    secretKey = ecc_point_to_128_bit_key(sharedECCKey)
    print("AES secretKey: " + binascii.hexlify(secretKey).decode('ascii'))

    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

msg = b'fortest'
print("original msg:\n", msg)

curve = registry.get_curve('brainpoolP256r1')
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

print("\nencrypt:")
encryptedMsg = encrypt_ECC(curve, msg, pubKey)
print("\nciphertext: " + binascii.hexlify(encryptedMsg[0]).decode('ascii'))
print("nonce: " + binascii.hexlify(encryptedMsg[1]).decode('ascii'))
print("authTag: " + binascii.hexlify(encryptedMsg[2]).decode('ascii'))
print("ciphertextPubKey: " + hex(encryptedMsg[3].x) + ", " + hex(encryptedMsg[3].y))

print("\ndecrypt:")
decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
print("\ndecrypted msg:\n", decryptedMsg)
