from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Demonstrates ECB mode leaking patterns
def ecb_vulnerability():
    key = b"16bytekey1234567"
    plaintext = b"SensitiveData123SensitiveData123"  # Repeating pattern

    # Encrypt
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print(f"Decrypted: {decrypted.decode()}")

ecb_vulnerability()
# Vulnerability: ECB mode leaks plaintext patterns in ciphertext.
