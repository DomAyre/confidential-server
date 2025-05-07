#include "base64.h"
#include <openssl/evp.h>
#include <stdlib.h>


char* base64_encode(
    const uint8_t* data,
    size_t input_length,
    size_t* output_length
) {
    if (!data) return NULL;

    // Calculate the output length (allocating if necessary)
    if (!output_length) {
        output_length = (size_t*)malloc(sizeof(size_t));
    }
    *output_length = 4 * ((input_length + 2) / 3);

    // Allocate space for the Base64-encoded string
    unsigned char* output = malloc(*output_length + 1);
    if (!output) return NULL;

    // EVP_EncodeBlock writes exactly 4 * ((in_len+2)/3) bytes (no '\0')
    int written = EVP_EncodeBlock(output, data, (int)input_length);
    if (written < 0) {
        free(output);
        return NULL;
    }

    // Null-terminate
    output[written] = '\0';

    return (char*)output;
}


uint8_t* base64_decode(
    const char* data,
    size_t input_length,
    size_t* output_length
) {
    if (!data) return NULL;

    // Handle empty input: return an allocatable empty buffer
    if (input_length == 0) {
        if (output_length) *output_length = 0;
        return malloc(1);
    }

    // Count padding characters '=' at the end
    size_t padding = 0;
    for (size_t i = input_length; i > 0 && data[i - 1] == '='; i--) {
        padding++;
    }

    // Calculate output length: 3 bytes per 4 Base64 chars
    if (!output_length) {
        output_length = (size_t*)malloc(sizeof(size_t));
    }
    *output_length = (input_length / 4) * 3;

    // Allocate space for the output
    unsigned char* output = malloc(*output_length);
    if (!output) return NULL;

    // EVP_DecodeBlock decodes input_length bytes and returns length (including padding)
    int decoded_len = EVP_DecodeBlock(output, (const unsigned char*)data, (int)input_length);
    if ((size_t)decoded_len != *output_length) {
        free(output);
        return NULL;
    }

    // Adjust length based on padding
    if (padding > 0) {
        *output_length -= (int)padding;
    }

    return output;
}
