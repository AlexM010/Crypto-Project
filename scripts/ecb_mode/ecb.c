#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

void aes_ecb_example() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[16] = "SixteenByteKey!";
    unsigned char plaintext[16] = "SensitiveData123";
    unsigned char ciphertext[16];

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    printf("AES in ECB mode encrypted data.\n");
    EVP_CIPHER_CTX_free(ctx);
}

void des_ecb_example() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[8] = "8bytekey";
    unsigned char plaintext[8] = "Data1234";
    unsigned char ciphertext[8];

    EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key, NULL);
    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext));
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    printf("DES in ECB mode encrypted data.\n");
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    aes_ecb_example();
    des_ecb_example();
    return 0;
}
