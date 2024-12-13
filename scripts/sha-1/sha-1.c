#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

void compute_sha1(const char *input) {
    SHA_CTX ctx;                          // Context for SHA-1
    unsigned char digest[SHA_DIGEST_LENGTH];

    SHA1_Init(&ctx);                      // Initialize SHA-1
    SHA1_Update(&ctx, input, strlen(input)); // Update with data
    SHA1_Final(digest, &ctx);             // Finalize hash

    printf("SHA-1 hash computed.\n");
}

int main() {
    const char *data = "test";
    compute_sha1(data);
    return 0;
}
