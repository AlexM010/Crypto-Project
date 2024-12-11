from Crypto.Cipher import DES
import os

# Example of using DES with a small key size
def des_vulnerability():
    key = b'8bytekey'  # DES requires an 8-byte key
    plaintext = b"SensitiveData123"

    # Encrypt
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext.ljust(16))  # Padding to make plaintext block size-compatible
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt
    decrypted = cipher.decrypt(ciphertext).strip()
    print(f"Decrypted: {decrypted.decode()}")

des_vulnerability()
# Vulnerability: DES's 56-bit key can be brute-forced in a reasonable time.
