#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>

int main() {
    unsigned char key[16] = "1234567890abcdef"; // AES-128 key (128 bits / 16 bytes)
    unsigned char data[16] = "Hello World";     // Data to encrypt
    unsigned char ciphertext[16];
    
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(data, ciphertext, &aes_key);
    
    printf("Ciphertext (AES-128): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");
    
    return 0;
}
