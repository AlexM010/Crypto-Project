import hashlib

# Demonstrates SHA-1 collision vulnerability
def sha1_vulnerability():
    data1 = b"message1"
    data2 = b"message2"

    hash1 = hashlib.sha1(data1).hexdigest()
    hash2 = hashlib.sha1(data2).hexdigest()

    print(f"SHA-1 hash of data1: {hash1}")
    print(f"SHA-1 hash of data2: {hash2}")
    # Vulnerability: SHA-1 is susceptible to collision attacks.

sha1_vulnerability()
