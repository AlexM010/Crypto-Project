#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

void aes_cbc_static_iv() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[16] = "SixteenByteKey!!";
    unsigned char iv[16] = "1234567890123456";  // Static IV (16 bytes for AES)
    unsigned char plaintext[16] = "Sensitive data!";
    unsigned char ciphertext[16];

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);  // Static IV used here
    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    printf("AES with static IV (CBC mode) encrypted data.\n");
    EVP_CIPHER_CTX_free(ctx);
}

void des_cbc_static_iv() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[8] = "8bytekey";
    unsigned char iv[8] = "12345678";  // Static IV (8 bytes for DES)
    unsigned char plaintext[8] = "Sensitive";
    unsigned char ciphertext[8];

    EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv);  // Static IV used here
    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    printf("DES with static IV (CBC mode) encrypted data.\n");
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    aes_cbc_static_iv();
    des_cbc_static_iv();
    return 0;
}
