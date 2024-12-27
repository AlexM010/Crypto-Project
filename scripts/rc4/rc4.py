from Crypto.Cipher import ARC4
key = b"12345678"  # Key for RC4
cipher = ARC4.new(key)
data = b"Hello World"
ciphertext = cipher.encrypt(data)
print("Ciphertext (RC4):", ciphertext)
decipher = ARC4.new(key)
decrypted = decipher.decrypt(ciphertext)
print("Decrypted (RC4):", decrypted)

