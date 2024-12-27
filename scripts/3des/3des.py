"""
test_3des_all.py
Demonstrates single-key (1-key), two-key (2-key), and three-key (3-key) 3DES usage in Python, all in one file.
We use PyCryptodome with DES3.new(...) calls that do both encrypt() and decrypt().
"""

from Crypto.Cipher import DES3

def test_singlekey_3des():
    """
    Single-key 3DES -> same 8-byte block repeated thrice => 24 bytes total.
    e.g., b"ABCDEFGHABCDEFGHABCDEFGH"
    """
    print("=== 3DES Single-Key (1-key) ===")
    cipher = DES3.new(b"ABCDEFGHABCDEFGHABCDEFGH", DES3.MODE_ECB)  # encrypt
    plaintext = b"SingleKey12345"
    ciphertext = cipher.encrypt(plaintext)
    print("Ciphertext (1-key):", ciphertext)

    decipher = DES3.new(b"ABCDEFGHABCDEFGHABCDEFGH", DES3.MODE_ECB)  # decrypt
    decrypted = decipher.decrypt(ciphertext)
    print("Decrypted (1-key):", decrypted, "\n")

def test_twokey_3des():
    """
    Two-key 3DES -> 16-byte key total, e.g. b"ABCDEFGHIJKLMNOP"
    """
    print("=== 3DES Two-Key (2-key) ===")
    cipher = DES3.new(b"ABCDEFGHIJKLMNOP", DES3.MODE_ECB)  # encrypt
    plaintext = b"TwoKeyExample123"
    ciphertext = cipher.encrypt(plaintext)
    print("Ciphertext (2-key):", ciphertext)

    decipher = DES3.new(b"ABCDEFGHIJKLMNOP", DES3.MODE_ECB)  # decrypt
    decrypted = decipher.decrypt(ciphertext)
    print("Decrypted (2-key):", decrypted, "\n")

def test_threekey_3des():
    """
    Three-key 3DES -> 24-byte key, not repeated thrice.
    e.g. b"ABCDEFGH12345678XYZ!12#@%"
    """
    print("=== 3DES Three-Key (3-key) ===")
    cipher = DES3.new(b"ABCDEFGH12345678XYZ!12#@", DES3.MODE_ECB)  # encrypt
    plaintext = b"ThreeKeyExample!"
    ciphertext = cipher.encrypt(plaintext)
    print("Ciphertext (3-key):", ciphertext)

    decipher = DES3.new(b"ABCDEFGH12345678XYZ!12#@", DES3.MODE_ECB)  # decrypt
    decrypted = decipher.decrypt(ciphertext)
    print("Decrypted (3-key):", decrypted, "\n")

if __name__ == "__main__":
    #test_singlekey_3des()
    test_twokey_3des()
    test_threekey_3des()
