#include <openssl/des.h>
#include <string.h>
#include <stdio.h>

int main() {
    DES_key_schedule key_schedule;
    unsigned char key[8] = "12345678";  // 56 bits key for DES
    DES_cblock input = "Hello   ";
    DES_cblock output;

    DES_set_key_unchecked(&key, &key_schedule);
    DES_ecb_encrypt(&input, &output, &key_schedule, DES_ENCRYPT);
    printf("Encrypted data: %s\n", output);
    return 0;
}
