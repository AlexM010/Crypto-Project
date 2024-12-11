#include <openssl/rc4.h>
#include <stdio.h>
#include <string.h>

int main() {
    RC4_KEY key;
    unsigned char key_data[8] = "12345678";  // Key for RC4
    unsigned char data[] = "Hello World";
    unsigned char output[128];

    RC4_set_key(&key, 8, key_data);  // Setting key size for RC4
    RC4(&key, sizeof(data), data, output);  // Encrypting
    printf("Ciphertext (RC4): %s\n", output);
    return 0;
}
