import hashlib

# Demonstrates MD5 collision vulnerability
def md5_vulnerability():
    data1 = b"message1"
    data2 = b"message2"

    hash1 = hashlib.md5(data1).hexdigest()
    hash2 = hashlib.md5(data2).hexdigest()

    print(f"MD5 hash of data1: {hash1}")
    print(f"MD5 hash of data2: {hash2}")
    # Vulnerability: MD5 can produce the same hash for different inputs (collision attacks).

md5_vulnerability()
