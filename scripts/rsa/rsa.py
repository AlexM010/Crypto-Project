from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# RSA-512: Generate a 512-bit key (insecure)
print("Testing RSA-512...")
rsa_512 = RSA.generate(1024)
message = b"Test RSA-512 encryption"
cipher_512 = PKCS1_v1_5.new(rsa_512.publickey())
encrypted_512 = cipher_512.encrypt(message)
print("RSA-512 Encrypted:", encrypted_512)

# RSA-2048: Generate a 2048-bit key (secure)
print("\nTesting RSA-2048...")
rsa_2048 = RSA.generate(2048)
cipher_2048 = PKCS1_v1_5.new(rsa_2048.publickey())
encrypted_2048 = cipher_2048.encrypt(message)
print("RSA-2048 Encrypted:", encrypted_2048)

print("\nTesting RSA No Padding...")
rsa_no_padding = RSA.generate(2048)
# WARNING: No built-in support for "no padding" in PyCryptodome, so emulate it by using low-level API.
#throws exception bcz of no padding
raw_message = b" " * (rsa_no_padding.size_in_bytes() - len(message)) + message  # Fill remaining bytes
encrypted_no_padding = rsa_no_padding.encrypt(raw_message, None)
print("RSA No Padding Encrypted:", encrypted_no_padding)
