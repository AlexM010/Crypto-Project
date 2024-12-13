#include <openssl/blowfish.h>
#include <stdio.h>
#include <string.h>

void blowfish_short_key_example() {
    BF_KEY bf_key;
    unsigned char key[8] = "shortkey";  // 8 bytes (64 bits)
    unsigned char plaintext[8] = "Data1234";
    unsigned char ciphertext[8];

    BF_set_key(&bf_key, 8, key);  // Setting a short key
    BF_ecb_encrypt(plaintext, ciphertext, &bf_key, BF_ENCRYPT);
    printf("Blowfish with short key (64 bits) encrypted data.\n");
}

int main() {
    blowfish_short_key_example();
    return 0;
}
