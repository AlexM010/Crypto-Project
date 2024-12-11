from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Demonstrates RSA vulnerability with short keys
def rsa_vulnerability():
    # Generate an insecure RSA key (512 bits)
    key = RSA.generate(512)
    plaintext = b"SensitiveData123"

    # Encrypt
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt
    decrypted = cipher.decrypt(ciphertext)
    print(f"Decrypted: {decrypted.decode()}")

rsa_vulnerability()
# Vulnerability: Short RSA keys (e.g., 512 bits) can be factored easily with modern computers.
