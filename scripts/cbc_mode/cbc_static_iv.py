from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad

# AES with static IV (predictable IV)
key = b"Sixteen byte key"
iv = b"1234567890123456"  # Static IV (16 bytes for AES)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(b"Sensitive data", AES.block_size))
print("AES with static IV (CBC mode):", ciphertext)

# DES with static IV (predictable IV)
key = b"8bytekey"
iv = b"12345678"  # Static IV (8 bytes for DES)
cipher = DES.new(key, DES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(b"Sensitive data", DES.block_size))
print("DES with static IV (CBC mode):", ciphertext)
