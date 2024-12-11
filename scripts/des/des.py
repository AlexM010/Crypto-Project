from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

key = get_random_bytes(8)  # 56 bits key for DES
cipher = DES.new(key, DES.MODE_ECB)
data = b"Hello World"
ciphertext = cipher.encrypt(data.ljust(8))
print("Ciphertext:", ciphertext)