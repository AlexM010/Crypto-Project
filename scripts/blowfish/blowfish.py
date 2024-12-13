from Crypto.Cipher import Blowfish

# Blowfish with short key (less than 128 bits)
key = b"shortkey"  # 8 bytes (64 bits)
cipher = Blowfish.new(key, Blowfish.MODE_ECB)
ciphertext = cipher.encrypt(b"Data1234")
print("Blowfish with short key (64 bits):", ciphertext)
