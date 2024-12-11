from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# AES-128 encryption example (16-byte key)
key = get_random_bytes(16)  # AES-128: 128-bit (16 bytes)
cipher = AES.new(key, AES.MODE_ECB)
data = b"Hello World"
ciphertext = cipher.encrypt(data.ljust(16))  # Padding to 16 bytes
print("Ciphertext (AES-128):", ciphertext)
