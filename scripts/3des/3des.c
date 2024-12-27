/*
  test_3des_all.c
  Demonstrates single-key, two-key, and three-key 3DES usage in a single file,
  using OpenSSL's EVP_EncryptInit_ex / EVP_DecryptInit_ex with hardcoded keys.

  Compile:
    gcc test_3des_all.c -lcrypto -o test_3des_all
  Run:
    ./test_3des_all
*/

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

static void test_singlekey_3des(void) {
    printf("=== 3DES Single-Key (1-key) ===\n");
    unsigned char plaintext[] = "SingleKey3DES";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int outlen, tmplen;

    // Single-key repeated 8 bytes => "ABCDEFGHABCDEFGHABCDEFGH"
    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx_enc, EVP_des_ede3_ecb(), NULL, "ABCDEFGHABCDEFGHABCDEFGH", NULL);
    EVP_EncryptUpdate(ctx_enc, ciphertext, &outlen, plaintext, strlen((char*)plaintext));
    EVP_EncryptFinal_ex(ctx_enc, ciphertext + outlen, &tmplen);
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx_enc);

    printf("Ciphertext length (1-key): %d\n", outlen);

    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx_dec, EVP_des_ede3_ecb(), NULL, "ABCDEFGHABCDEFGHABCDEFGH", NULL);
    int declen, tmpdeclen;
    EVP_DecryptUpdate(ctx_dec, decrypted, &declen, ciphertext, outlen);
    EVP_DecryptFinal_ex(ctx_dec, decrypted + declen, &tmpdeclen);
    declen += tmpdeclen;
    decrypted[declen] = '\0';
    EVP_CIPHER_CTX_free(ctx_dec);

    printf("Decrypted (1-key): %s\n\n", decrypted);
}

static void test_twokey_3des(void) {
    printf("=== 3DES Two-Key (2-key) ===\n");
    unsigned char plaintext[] = "TwoKey3DESExample";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int outlen, tmplen;

    // Two-key => 16 bytes e.g. "ABCDEFGHIJKLMNOP"
    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx_enc, EVP_des_ede3_ecb(), NULL, "ABCDEFGHIJKLMNOP", NULL);
    EVP_EncryptUpdate(ctx_enc, ciphertext, &outlen, plaintext, strlen((char*)plaintext));
    EVP_EncryptFinal_ex(ctx_enc, ciphertext + outlen, &tmplen);
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx_enc);

    printf("Ciphertext length (2-key): %d\n", outlen);

    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx_dec, EVP_des_ede3_ecb(), NULL, "ABCDEFGHIJKLMNOP", NULL);
    int declen, tmpdeclen;
    EVP_DecryptUpdate(ctx_dec, decrypted, &declen, ciphertext, outlen);
    EVP_DecryptFinal_ex(ctx_dec, decrypted + declen, &tmpdeclen);
    declen += tmpdeclen;
    decrypted[declen] = '\0';
    EVP_CIPHER_CTX_free(ctx_dec);

    printf("Decrypted (2-key): %s\n\n", decrypted);
}

static void test_threekey_3des(void) {
    printf("=== 3DES Three-Key (3-key) ===\n");
    unsigned char plaintext[] = "ThreeKey3DESTest!";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int outlen, tmplen;

    // Three-key => 24 bytes, e.g. "ABCDEFGH12345678XYZ!12#@"
    EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx_enc, EVP_des_ede3_ecb(), NULL, "ABCDEFGH12345678XYZ!12#@", NULL);
    EVP_EncryptUpdate(ctx_enc, ciphertext, &outlen, plaintext, strlen((char*)plaintext));
    EVP_EncryptFinal_ex(ctx_enc, ciphertext + outlen, &tmplen);
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx_enc);

    printf("Ciphertext length (3-key): %d\n", outlen);

    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx_dec, EVP_des_ede3_ecb(), NULL, "ABCDEFGH12345678XYZ!12#@", NULL);
    int declen, tmpdeclen;
    EVP_DecryptUpdate(ctx_dec, decrypted, &declen, ciphertext, outlen);
    EVP_DecryptFinal_ex(ctx_dec, decrypted + declen, &tmpdeclen);
    declen += tmpdeclen;
    decrypted[declen] = '\0';
    EVP_CIPHER_CTX_free(ctx_dec);

    printf("Decrypted (3-key): %s\n\n", decrypted);
}

int main(void) {
    test_singlekey_3des();
    test_twokey_3des();
    test_threekey_3des();
    return 0;
}
