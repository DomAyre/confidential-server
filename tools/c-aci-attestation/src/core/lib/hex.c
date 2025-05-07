#include "hex.h"
#include <stdlib.h>
#include <ctype.h>

// Encodes binary data to a null-terminated lowercase hexadecimal string.
char* hex_encode(const uint8_t* data, size_t input_length, size_t* output_length) {
    if (!data) return NULL;
    // Two hex chars per byte plus one space between bytes (except last): total = input_length * 3 - 1
    size_t out_len = (input_length == 0) ? 0 : (input_length * 3 - 1);
    char* out = malloc(out_len + 1);
    if (!out) return NULL;
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < input_length; i++) {
        uint8_t byte = data[i];
        size_t pos = i * 3;
        out[pos]     = hex_digits[(byte >> 4) & 0xF];
        out[pos + 1] = hex_digits[byte & 0xF];
        if (i + 1 < input_length) {
            out[pos + 2] = ' ';
        }
    }
    out[out_len] = '\0';
    if (output_length) *output_length = out_len;
    return out;
}

// Decodes a hexadecimal string into binary data.
uint8_t* hex_decode(const char* hex, size_t input_length, size_t* output_length) {
    if (!hex) return NULL;
    // Count hex digits, skip whitespace
    size_t digit_count = 0;
    for (size_t i = 0; i < input_length; i++) {
        if (isxdigit((unsigned char)hex[i])) {
            digit_count++;
        } else if (isspace((unsigned char)hex[i])) {
            continue;
        } else {
            return NULL;
        }
    }
    if (digit_count % 2 != 0) return NULL;
    size_t out_len = digit_count / 2;
    // Handle empty output: allocate at least one byte so caller can free()
    if (out_len == 0) {
        if (output_length) *output_length = 0;
        return malloc(1);
    }
    uint8_t* out = malloc(out_len);
    if (!out) return NULL;
    size_t di = 0; // index in hex
    size_t oi = 0; // index in out
    while (oi < out_len) {
        // read high nibble
        int vhi = -1;
        while (di < input_length) {
            char c = hex[di++];
            if (isxdigit((unsigned char)c)) {
                vhi = (isdigit((unsigned char)c) ? c - '0' : (isupper((unsigned char)c) ? c - 'A' + 10 : c - 'a' + 10));
                break;
            }
            // skip whitespace
        }
        if (vhi < 0) { free(out); return NULL; }
        // read low nibble
        int vlo = -1;
        while (di < input_length) {
            char c = hex[di++];
            if (isxdigit((unsigned char)c)) {
                vlo = (isdigit((unsigned char)c) ? c - '0' : (isupper((unsigned char)c) ? c - 'A' + 10 : c - 'a' + 10));
                break;
            }
        }
        if (vlo < 0) { free(out); return NULL; }
        out[oi++] = (uint8_t)((vhi << 4) | vlo);
    }
    if (output_length) *output_length = out_len;
    return out;
}