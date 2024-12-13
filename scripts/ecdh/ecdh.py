from Crypto.Protocol.KDF import ECDH
from Crypto.PublicKey import ECC

# Example ECDH key agreement
private_key = ECC.generate(curve="P-256")
peer_key = ECC.generate(curve="P-256").public_key()
ecdh = ECDH()
ecdh.load_private_key(private_key)
shared_secret = ecdh.generate_shared_secret(peer_key)
print("ECDH shared secret:", shared_secret)
