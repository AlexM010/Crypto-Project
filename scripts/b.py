from arc4 import ARC4

# Demonstrates RC4's predictable keystream
def rc4_vulnerability():
    key = b"key"
    plaintext = b"SensitiveData123"
    rc4 = ARC4(key)

    # Encrypt
    ciphertext = rc4.encrypt(plaintext)
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt
    rc4 = ARC4(key)  # Reset RC4 with the same key
    decrypted = rc4.decrypt(ciphertext)
    print(f"Decrypted: {decrypted.decode()}")

rc4_vulnerability()
# Vulnerability: RC4 keystream bias makes it insecure for cryptographic use.
