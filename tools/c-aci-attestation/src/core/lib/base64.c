// base64.c - Wrapper around OpenSSL EVP_EncodeBlock
#include "base64.h"
#include <openssl/evp.h>
#include <stdlib.h>

// Encodes the input data using OpenSSL EVP_EncodeBlock (standard Base64, no line breaks).
// Returns a malloc'd null-terminated string, or NULL on failure.
char* base64_encode(const uint8_t* data,
                     size_t input_length,
                     size_t* output_length) {
    // Calculate required output length: 4 * ceil(input_length/3)
    size_t olen = 4 * ((input_length + 2) / 3);
    unsigned char* encoded = malloc(olen + 1);
    if (!encoded) return NULL;
    // EVP_EncodeBlock writes exactly 4 * ((in_len+2)/3) bytes (no '\0')
    int written = EVP_EncodeBlock(encoded, data, (int)input_length);
    if (written < 0) {
        free(encoded);
        return NULL;
    }
    // Null-terminate
    encoded[written] = '\0';
    if (output_length) *output_length = (size_t)written;
    return (char*)encoded;
}