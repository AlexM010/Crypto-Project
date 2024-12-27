/*
  test_aes192.c
  Demonstrates AES-192 in C with OpenSSL. Uses a 24-byte key literally
  and calls EVP_EncryptInit_ex/EVP_DecryptInit_ex for encryption/decryption.

  Compile:
    gcc test_aes192.c -lcrypto -o test_aes192
  Run:
    ./test_aes192
*/

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

// 24-byte AES-192 key
static const unsigned char key192[24] = "0123456789ABCDEFG012345";

static void test_aes192(void) {
    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();

    const EVP_CIPHER *cipher = EVP_aes_192_ecb(); // triggers AES-192 pattern

    unsigned char plaintext[] = "HelloAES192_C";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int out_len, final_len;

    printf("=== AES-192 Test ===\n");

    // ENCRYPT
    EVP_EncryptInit_ex(ctx_enc, cipher, NULL, key192, NULL);
    EVP_EncryptUpdate(ctx_enc, ciphertext, &out_len, plaintext, strlen((char*)plaintext));
    EVP_EncryptFinal_ex(ctx_enc, ciphertext + out_len, &final_len);
    out_len += final_len;

    printf("Ciphertext length (192): %d\n", out_len);

    // DECRYPT
    EVP_DecryptInit_ex(ctx_dec, cipher, NULL, key192, NULL);
    int dec_len, final_dec_len;
    EVP_DecryptUpdate(ctx_dec, decrypted, &dec_len, ciphertext, out_len);
    EVP_DecryptFinal_ex(ctx_dec, decrypted + dec_len, &final_dec_len);
    dec_len += final_dec_len;
    decrypted[dec_len] = '\0';

    printf("Decrypted (192): %s\n\n", decrypted);

    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);
}

int main(void) {
    test_aes192();
    return 0;
}
