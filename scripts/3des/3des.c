#include <openssl/des.h>
#include <string.h>
#include <stdio.h>

int main() {
    DES_key_schedule key_schedule1, key_schedule2, key_schedule3;
    unsigned char key[8] = "12345678";  // 56-bit key for DES
    unsigned char key2[8] = "87654321"; // Another 56-bit key for 3DES with 2 keys
    unsigned char key3[8] = "abcdef01"; // Another 56-bit key for 3DES with 3 keys
    DES_cblock input = "Hello World";
    DES_cblock output;

    DES_set_key_unchecked(&key, &key_schedule1);
    DES_set_key_unchecked(&key2, &key_schedule2);
    DES_set_key_unchecked(&key3, &key_schedule3);
    
    // 3DES with 1 key
    DES_ecb_encrypt(&input, &output, &key_schedule1, DES_ENCRYPT);
    printf("Encrypted data (3DES with 1 key): %s\n", output);
    
    // 3DES with 2 keys
    DES_ecb_encrypt(&input, &output, &key_schedule1, DES_ENCRYPT);
    DES_ecb_encrypt(&output, &output, &key_schedule2, DES_DECRYPT);
    printf("Encrypted data (3DES with 2 keys): %s\n", output);
    
    // 3DES with 3 keys
    DES_ecb_encrypt(&input, &output, &key_schedule1, DES_ENCRYPT);
    DES_ecb_encrypt(&output, &output, &key_schedule2, DES_DECRYPT);
    DES_ecb_encrypt(&output, &output, &key_schedule3, DES_ENCRYPT);
    printf("Encrypted data (3DES with 3 keys): %s\n", output);
    
    return 0;
}
