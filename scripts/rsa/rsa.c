#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main() {
    RSA *rsa_512 = RSA_generate_key(512, RSA_F4, NULL, NULL);  // RSA 512-bit
    RSA *rsa_1024 = RSA_generate_key(1024, RSA_F4, NULL, NULL);  // RSA 1024-bit
    printf("RSA 512 and 1024 bit keys generated.\n");

    return 0;
}
