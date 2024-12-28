#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    unsigned char message[256] = {0};
    unsigned char encrypted[256];
    unsigned char decrypted[256];
    int encrypted_length, decrypted_length;
    strcpy(message,"Test RSA Encryption");
    // RSA-512
    printf("Testing RSA-512...\n");
    RSA *rsa_512 = RSA_generate_key(512, RSA_F4, NULL, NULL);
    encrypted_length = RSA_public_encrypt(strlen(message), message, encrypted, rsa_512, RSA_PKCS1_PADDING);
    if (encrypted_length == -1) handleErrors();
    printf("RSA-512 Encrypted: %s\n", encrypted);

    // RSA-2048
    printf("\nTesting RSA-2048...\n");
    RSA *rsa_2048 = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    encrypted_length = RSA_public_encrypt(strlen(message), message, encrypted, rsa_2048, RSA_PKCS1_PADDING);
    if (encrypted_length == -1) handleErrors();
    printf("RSA-2048 Encrypted: %s\n", encrypted);

    // RSA No Padding
    printf("\nTesting RSA No Padding...\n");
    RSA *rsa_no_padding = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    encrypted_length = RSA_public_encrypt(256, message, encrypted, rsa_no_padding, RSA_NO_PADDING);
    if (encrypted_length == -1) handleErrors();
    printf("RSA No Padding Encrypted: %s\n", encrypted);

    RSA_free(rsa_512);
    RSA_free(rsa_2048);
    RSA_free(rsa_no_padding);
    return 0;
}
