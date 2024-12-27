"""
test_aes192.py
Demonstrates AES-192 usage in Python (PyCryptodome).
Single-line call with 24-byte literal in AES.new(...).
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad

def test_aes192():
    print("=== AES-192 Test ===")
    # 24-byte key => b"1234567890ABCDEF12345678"
    cipher = AES.new(b"1234567890ABCDEF12345678", AES.MODE_ECB)
    plaintext = b"HelloAES192Test"
    ciphertext = cipher.encrypt(pad(plaintext,cipher.block_size))
    print("Ciphertext (192):", ciphertext)

    decipher = AES.new(b"1234567890ABCDEF12345678", AES.MODE_ECB)
    decrypted = decipher.decrypt(ciphertext)
    print("Decrypted (192):", unpad(decrypted, decipher.block_size), "\n")

if __name__ == "__main__":
    test_aes192()
