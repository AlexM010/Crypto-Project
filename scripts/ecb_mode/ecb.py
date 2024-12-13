from Crypto.Cipher import AES, DES

# AES with ECB mode
aes_ecb = AES.new(b"Sixteen byte key", AES.MODE_ECB)
ciphertext = aes_ecb.encrypt(b"Sensitive data!!")
print("AES in ECB mode:", ciphertext)

# DES with ECB mode
des_ecb = DES.new(b"8bytekey", DES.MODE_ECB)
ciphertext = des_ecb.encrypt(b"Data1234")
print("DES in ECB mode:", ciphertext)
