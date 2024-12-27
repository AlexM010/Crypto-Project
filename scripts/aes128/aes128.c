/*
  test_aes128.c
  Demonstrates AES-128 in C with OpenSSL. Uses a 16-byte key literally
  and calls EVP_EncryptInit_ex/EVP_DecryptInit_ex for a minimal example.

  Compile:
    gcc test_aes128.c -lcrypto -o test_aes128
  Run:
    ./test_aes128
*/

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

// 16-byte AES-128 key
static const unsigned char key128[16] = "0123456789ABCDEF";

// We'll do ECB for simplicity (not secure for real use!)
static void test_aes128(void) {
    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();

    const EVP_CIPHER *cipher = EVP_aes_128_ecb(); // triggers AES-128 pattern

    // Data to encrypt
    unsigned char plaintext[] = "HelloAES128_C";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int out_len, final_len;

    printf("=== AES-128 Test ===\n");

    // ENCRYPT
    EVP_EncryptInit_ex(ctx_enc, cipher, NULL, key128, NULL);
    EVP_EncryptUpdate(ctx_enc, ciphertext, &out_len, plaintext, strlen((char*)plaintext));
    EVP_EncryptFinal_ex(ctx_enc, ciphertext + out_len, &final_len);
    out_len += final_len;

    printf("Ciphertext length (128): %d\n", out_len);

    // DECRYPT
    EVP_DecryptInit_ex(ctx_dec, cipher, NULL, key128, NULL);
    int dec_len, final_dec_len;
    EVP_DecryptUpdate(ctx_dec, decrypted, &dec_len, ciphertext, out_len);
    EVP_DecryptFinal_ex(ctx_dec, decrypted + dec_len, &final_dec_len);
    dec_len += final_dec_len;
    decrypted[dec_len] = '\0';

    printf("Decrypted (128): %s\n\n", decrypted);

    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);
}

int main(void) {
    test_aes128();
    return 0;
}
