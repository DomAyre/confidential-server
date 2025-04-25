#include <stdint.h>
#include <stddef.h>

#ifndef BASE64_H
#define BASE64_H

// Encodes the input data to a null-terminated Base64 string (standard alphabet).
// data: pointer to input bytes.
// input_length: length of input in bytes.
// output_length: pointer to size_t to store length of encoded output (excluding null terminator).
// Returns allocated null-terminated encoded string, or NULL on failure. Caller must free() the returned string.
char* base64_encode(const uint8_t* data, size_t input_length, size_t* output_length);

#endif // BASE64_H