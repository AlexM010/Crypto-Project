from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

key = get_random_bytes(8)  # 56-bit key
cipher = DES3.new(key + key + key, DES3.MODE_ECB)  # 3DES with 1 key (56 * 3)
data = b"Hello World"
ciphertext = cipher.encrypt(data.ljust(24))
print("Ciphertext (3DES with 1 key):", ciphertext)

key2 = get_random_bytes(16)  # 128-bit key
cipher2 = DES3.new(key2 + key2[:8], DES3.MODE_ECB)  # 3DES with 2 keys
ciphertext2 = cipher2.encrypt(data.ljust(24))
print("Ciphertext (3DES with 2 keys):", ciphertext2)

key3 = get_random_bytes(24)  # 192-bit key
cipher3 = DES3.new(key3, DES3.MODE_ECB)  # 3DES with 3 keys
ciphertext3 = cipher3.encrypt(data.ljust(24))
print("Ciphertext (3DES with 3 keys):", ciphertext3)
