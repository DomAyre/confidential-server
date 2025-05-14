/*
 * Simple COSE_Sign1 structure checker.
 * Provides a minimal check that a buffer is a COSE_Sign1 message by
 * verifying the CBOR tag and array header.
 */
#ifndef COSE_H
#define COSE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get the payload from a COSE_Sign1 structure.
 * Returns a pointer to the payload, or NULL on failure.
 * The caller is responsible for freeing the returned pointer.
 */
char* get_cose_payload(const uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif // COSE_H