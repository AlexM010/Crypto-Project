#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

void compute_sha256(const char *input) {
    SHA256_CTX ctx;                       // Context for SHA-256
    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256_Init(&ctx);                    // Initialize SHA-256
    SHA256_Update(&ctx, input, strlen(input)); // Update with data
    SHA256_Final(digest, &ctx);           // Finalize hash

    printf("SHA-256 hash computed.\n");

    //print digest
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

int main() {
    const char *data = "test";
    compute_sha256(data);
    return 0;
}
