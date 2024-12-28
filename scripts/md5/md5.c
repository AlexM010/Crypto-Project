#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>

void compute_md5(const char *input) {
    MD5_CTX ctx;                          // Context for MD5
    unsigned char digest[MD5_DIGEST_LENGTH];

    MD5_Init(&ctx);                       // Initialize MD5
    MD5_Update(&ctx, input, strlen(input)); // Update with data
    MD5_Final(digest, &ctx);              // Finalize hash

    printf("MD5 hash computed.\n");

    //print digest
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

}

int main() {
    const char *data = "test";
    compute_md5(data);
    return 0;
}
