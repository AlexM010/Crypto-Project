"""
test_blowfish_shortkey.py
Uses PyCryptodome Blowfish with a short key (<16 bytes) as a byte literal.
"""

from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad,unpad

def test_blowfish_short_key():
    print("=== Blowfish Short Key Test (Python) ===")

    # Single-line with a short (8-byte) key: b"shrtkey!"
    cipher = Blowfish.new(key=b"shrtkey!", mode=Blowfish.MODE_ECB)  # 9 bytes
    plaintext = b"HelloBfish"
    # Blowfish block size is 8, so you might do PKCS5 padding in real usage.
    ciphertext = cipher.encrypt(pad(plaintext,cipher.block_size))  # Just quick padding to multiple of 8
    print("Ciphertext:", ciphertext)

    decipher = Blowfish.new(key=b"shrtkey!", mode=Blowfish.MODE_ECB)
    decrypted = decipher.decrypt(ciphertext)
    print("Decrypted:", unpad(decrypted,decipher.block_size))

if __name__ == "__main__":
    test_blowfish_short_key()
