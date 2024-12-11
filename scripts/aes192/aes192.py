from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# AES-192 encryption example (24-byte key)
key = get_random_bytes(24)  # AES-192: 192-bit (24 bytes)
cipher = AES.new(key, AES.MODE_ECB)
data = b"Hello World"
ciphertext = cipher.encrypt(data.ljust(24))  # Padding to 24 bytes
print("Ciphertext (AES-192):", ciphertext)
