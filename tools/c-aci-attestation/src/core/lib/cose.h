/*
 * Simple COSE_Sign1 structure checker.
 * Provides a minimal check that a buffer is a COSE_Sign1 message by
 * verifying the CBOR tag and array header.
 */
#ifndef COSE_H
#define COSE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int64_t alg;
    char* content_type;
    // uint8_t** x5_chain;      // Array of pointers to byte arrays
    // size_t* x5_chain_lens;   // Array of lengths for each certificate
    // size_t x5_chain_count;   // Number of certificates in the chain
    char* iss;
    char* feed;
} COSE_Sign1_Protected_Header;

typedef struct {
    COSE_Sign1_Protected_Header* protected_header;
    uint8_t* payload;
} COSE_Sign1;


/**
 * Get the payload from a COSE_Sign1 structure.
 * Returns a pointer to the payload, or NULL on failure.
 * The caller is responsible for freeing the returned pointer.
 */
COSE_Sign1* parse_cose_sign1(const uint8_t* buf, size_t len);


#endif // COSE_H