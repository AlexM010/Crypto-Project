#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main() {
    RSA *rsa_512 = RSA_generate_key(512, RSA_F4, NULL, NULL);  // RSA 512-bit
    RSA *rsa_1024 = RSA_generate_key(1024, RSA_F4, NULL, NULL);  // RSA 1024-bit
    printf("RSA 512 and 1024 bit keys generated.\n");

    //encrypt
    unsigned char plaintext[128] = "Hello RSA";  // 10 chars + null
    unsigned char ciphertext[128];
    RSA_public_encrypt(11, plaintext, ciphertext, rsa_512, RSA_PKCS1_PADDING);
    printf("Ciphertext (RSA 512-bit): %s\n", ciphertext);
    RSA_public_encrypt(11, plaintext, ciphertext, rsa_1024, RSA_PKCS1_PADDING);
    printf("Ciphertext (RSA 1024-bit): %s\n", ciphertext);
    //decrypt plaintext
    unsigned char decrypted[128];
    RSA_private_decrypt(128, ciphertext, decrypted, rsa_512, RSA_PKCS1_PADDING);
    printf("Decrypted (RSA 512-bit): %s\n", decrypted);
    RSA_private_decrypt(128, ciphertext, decrypted, rsa_1024, RSA_PKCS1_PADDING);
    printf("Decrypted (RSA 1024-bit): %s\n", decrypted);
    

    return 0;
}
