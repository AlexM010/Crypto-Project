"""
test_aes128.py
Demonstrates AES-128 usage in Python (PyCryptodome).
Single-line call with 16-byte literal in AES.new(...).
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad
def test_aes128():
    print("=== AES-128 Test ===")
    # 16-byte key => b"1234567890ABCDEF"
    cipher = AES.new(b"1234567890ABCDEF", AES.MODE_ECB)
    plaintext = b"HelloAES128"
    ciphertext = cipher.encrypt(pad(plaintext,cipher.block_size))
    print("Ciphertext (128):", ciphertext)

    decipher = AES.new(b"1234567890ABCDEF", AES.MODE_ECB)
    decrypted = decipher.decrypt(ciphertext)
    print("Decrypted (128):", unpad(decrypted,cipher.block_size), "\n")

if __name__ == "__main__":
    test_aes128()
