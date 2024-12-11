from Crypto.PublicKey import RSA

# RSA with short keys (512 and 1024 bits)
key_512 = RSA.generate(512)  # Vulnerable: RSA 512 bits
key_1024 = RSA.generate(1024)  # Vulnerable: RSA 1024 bits
print(key_512.export_key().decode())
print(key_1024.export_key().decode())
