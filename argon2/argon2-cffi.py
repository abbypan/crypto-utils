from argon2 import PasswordHasher, Type
 
ph = PasswordHasher(
    memory_cost=65536,
    time_cost=4,
    parallelism=3,
    hash_len=32,
    type=Type.ID
)
 
password = 'Hello World'
passwordHash = ph.hash(password)
 
print(passwordHash)
