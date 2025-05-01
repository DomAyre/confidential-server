#include "sha256.h"
#include <openssl/sha.h>
#include <stdlib.h>

uint8_t* sha256(const uint8_t* data, size_t length) {
    if (!data) return NULL;
    uint8_t* digest = malloc(SHA256_DIGEST_LENGTH);
    if (!digest) return NULL;
    SHA256_CTX ctx;
    if (SHA256_Init(&ctx) != 1) {
        free(digest);
        return NULL;
    }
    if (SHA256_Update(&ctx, data, length) != 1) {
        free(digest);
        return NULL;
    }
    if (SHA256_Final(digest, &ctx) != 1) {
        free(digest);
        return NULL;
    }
    return digest;
}