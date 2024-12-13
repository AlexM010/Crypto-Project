#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>

int main() {
    EC_KEY *key1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY *key2 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    // Generate keys
    EC_KEY_generate_key(key1);
    EC_KEY_generate_key(key2);

    // Derive shared secret
    const EC_POINT *pub_key2 = EC_KEY_get0_public_key(key2);
    unsigned char secret[32];
    ECDH_compute_key(secret, sizeof(secret), pub_key2, key1, NULL);
    printf("ECDH shared secret computed.\n");

    EC_KEY_free(key1);
    EC_KEY_free(key2);
    return 0;
}