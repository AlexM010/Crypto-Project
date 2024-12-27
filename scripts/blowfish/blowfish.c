/*
  test_blowfish_shortkey_fixed.c
  Demonstrates Blowfish with a short key in C (ECB, two blocks).
  Compile:
    gcc test_blowfish_shortkey_fixed.c -lcrypto -o test_blowfish_shortkey_fixed
*/

#include <stdio.h>
#include <string.h>
#include <openssl/blowfish.h>

int main(void) {
    printf("=== Blowfish Short Key Test (C) ===\n");

    BF_KEY bf_key;
    // short key, 9 bytes => "shrtkey!"
    BF_set_key(&bf_key,5 , (const unsigned char*)"shrtkey!");

    unsigned char plaintext[16] = "HelloBlowfishC"; // 11 chars + null
    memset(plaintext + 14, 0, 2);                   // pad last 2 bytes with 0
    printf("Plaintext: %s\n", plaintext);

    // We'll encrypt in two 8-byte blocks
    unsigned char block1[8], block2[8];
    memcpy(block1, plaintext, 8);
    memcpy(block2, plaintext + 8, 8);

    unsigned char ciph1[8], ciph2[8];
    BF_ecb_encrypt(block1, ciph1, &bf_key, BF_ENCRYPT);
    BF_ecb_encrypt(block2, ciph2, &bf_key, BF_ENCRYPT);

    // Show ciphertext (not easily printable, but just for demonstration)
    printf("Ciphertext block1: ");
    for(int i=0; i<8; i++) printf("%02X ", ciph1[i]);
    printf("\nCiphertext block2: ");
    for(int i=0; i<8; i++) printf("%02X ", ciph2[i]);
    printf("\n");

    // Decrypt the two blocks
    unsigned char dec1[8], dec2[8];
    BF_ecb_encrypt(ciph1, dec1, &bf_key, BF_DECRYPT);
    BF_ecb_encrypt(ciph2, dec2, &bf_key, BF_DECRYPT);

    unsigned char decrypted[16];
    memcpy(decrypted, dec1, 8);
    memcpy(decrypted + 8, dec2, 8);

    printf("Decrypted: %s\n", decrypted);

    return 0;
}
