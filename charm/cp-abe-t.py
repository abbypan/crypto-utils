#!/usr/bin/python3

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)

(master_public_key, master_secret_key) = cpabe.setup()

dog_attributes = ['DOG', 'TOFU']
dog_secret_key = cpabe.keygen(master_public_key, master_secret_key, dog_attributes)

cat_attributes = ['CAT', 'TOFU']
cat_secret_key = cpabe.keygen(master_public_key, master_secret_key, cat_attributes)

policy = '(DOG AND TOFU)'  

print("Encryption:\n")
ek = group.random(GT)

ciphertext = cpabe.encrypt(master_public_key, ek, policy)

print("ciphertext:", ciphertext, "\n")
print("ek:", ek, "\n")

print("Decryption:\n")
dog_decrypted_ek = cpabe.decrypt(master_public_key, dog_secret_key, ciphertext)
if dog_decrypted_ek is False:
    print("dog Decryption failed.\n")
else:
    print("dog Decrypted ek successful:", dog_decrypted_ek, "\n")


cat_decrypted_ek = cpabe.decrypt(master_public_key, cat_secret_key, ciphertext)
if cat_decrypted_ek is False:
    print("cat Decryption failed.\n")
else:
    print("cat Decrypted ek successful:", cat_decrypted_ek, "\n")


