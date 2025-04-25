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
// Decodes Base64-encoded data using OpenSSL EVP_DecodeBlock.
// Returns a malloc'd buffer containing the decoded bytes, or NULL on failure.
uint8_t* base64_decode(const char* data,
                       size_t input_length,
                       size_t* output_length) {
    if (!data) return NULL;
    // Count padding characters '=' at the end
    size_t padding = 0;
    if (input_length >= 1 && data[input_length - 1] == '=') padding++;
    if (input_length >= 2 && data[input_length - 2] == '=') padding++;
    // Calculate maximum decoded length: 3 bytes per 4 Base64 chars
    size_t alloc_len = (input_length / 4) * 3;
    unsigned char* decoded = malloc(alloc_len);
    if (!decoded) return NULL;
    // EVP_DecodeBlock decodes input_length bytes and returns length (including padding)
    int decoded_len = EVP_DecodeBlock(decoded,
                                      (const unsigned char*)data,
                                      (int)input_length);
    if (decoded_len < 0) {
        free(decoded);
        return NULL;
    }
    // Adjust length based on padding
    if (padding > 0) {
        decoded_len -= (int)padding;
        if (decoded_len < 0) decoded_len = 0;
    }
    if (output_length) *output_length = (size_t)decoded_len;
    return decoded;
}
