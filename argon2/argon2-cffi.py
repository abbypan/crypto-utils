#!/usr/bin/python3

import sys
import hashlib
import binascii
from argon2 import PasswordHasher, Type, exceptions

#RFC9106

def argon2_calc_hash(password):

    ph = PasswordHasher(
        memory_cost=65536, 
        time_cost=3,       
        parallelism=4,     
        hash_len=32,       
        salt_len=16,        
        type=Type.ID
    )

    hashed = ph.hash(password)
    #return binascii.hexlify(hashed).decode('utf-8')

    return hashed

def argon2_verify(hashed, password):

    ph = PasswordHasher(
        memory_cost=65536, 
        time_cost=3,       
        parallelism=4,     
        hash_len=32,       
        salt_len=16,        
        type=Type.ID
    )

    try:
        return ph.verify(hashed, password)

    except exceptions.VerifyMismatchError:
        print(f"mismatch: {e}")
        return False

    except exceptions.VerificationError as e:
        print(f"verify err: {e}")
        return False

    except exceptions.InvalidHashError as e:
        print(f"invalid: {e}")
        return False

#password = bytes.fromhex(sys.argv[1])

password = sys.argv[1].encode("utf-8")

hashed = argon2_calc_hash(password)

verify_res=argon2_verify(hashed, password)

print("password: ", password, "\nargon2: ", hashed, "\nverify result: ", verify_res)



