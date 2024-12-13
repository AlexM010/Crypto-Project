from cryptography.hazmat.primitives.asymmetric import dh

# Weak parameters: Small modulus size
parameters = dh.generate_parameters(generator=2, key_size=1024)
private_key = parameters.generate_private_key()
print("Diffie-Hellman with weak parameters (1024-bit modulus).")

# General Diffie-Hellman setup (quantum threat)
parameters = dh.generate_parameters(generator=2, key_size=2048)
private_key = parameters.generate_private_key()
print("Diffie-Hellman setup (quantum threat).")
