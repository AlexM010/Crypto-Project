from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad , unpad

key = get_random_bytes(8)  # 56 bits key for DES
cipher = DES.new(key, DES.MODE_ECB)
data = b"HelloWorld"
ciphertext = cipher.encrypt(pad(data,DES.block_size)) 
print("Ciphertext:", ciphertext)
#decrypt(ciphertext
plaintext = unpad(cipher.decrypt(ciphertext),DES.block_size)
print("Plaintext:", plaintext)
