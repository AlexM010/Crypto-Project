#include <openssl/dh.h>
#include <stdio.h>

void dh_weak_parameters() {
    DH *dh = DH_new();
    int prime_length = 1024;  // Weak prime modulus size
    DH_generate_parameters_ex(dh, prime_length, DH_GENERATOR_2, NULL);
    printf("Diffie-Hellman with weak parameters (1024-bit modulus).\n");
    DH_free(dh);
}

void dh_quantum_threat() {
    DH *dh = DH_new();
    int prime_length = 2048;  // Standard modulus size (quantum threat)
    DH_generate_parameters_ex(dh, prime_length, DH_GENERATOR_2, NULL);
    printf("Diffie-Hellman setup (quantum threat).\n");
    DH_free(dh);
}

int main() {
    dh_weak_parameters();
    dh_quantum_threat();
    return 0;
}
