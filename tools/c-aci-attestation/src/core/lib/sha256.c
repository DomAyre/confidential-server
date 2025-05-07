#include "sha256.h"
#include <openssl/evp.h>
#include <stdlib.h>

uint8_t* sha256(const uint8_t* data, size_t length) {
    if (!data) return NULL;
    size_t digest_len = EVP_MD_size(EVP_sha256());
    uint8_t* digest = malloc(digest_len);
    if (!digest) return NULL;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(digest);
        return NULL;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        free(digest);
        return NULL;
    }
    if (EVP_DigestUpdate(ctx, data, length) != 1) {
        EVP_MD_CTX_free(ctx);
        free(digest);
        return NULL;
    }
    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &out_len) != 1) {
        EVP_MD_CTX_free(ctx);
        free(digest);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);
    if ((size_t)out_len != digest_len) {
        free(digest);
        return NULL;
    }
    return digest;
}