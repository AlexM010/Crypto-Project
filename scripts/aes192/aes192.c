#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>

int main() {
    unsigned char key[24] = "123456789012345678901234";  // AES-192 key (192 bits / 24 bytes)
    unsigned char data[24] = "Hello World";              // Data to encrypt
    unsigned char ciphertext[24];
    
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 192, &aes_key);
    AES_encrypt(data, ciphertext, &aes_key);
    
    printf("Ciphertext (AES-192): ");
    for (int i = 0; i < 24; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");
    
    return 0;
}
