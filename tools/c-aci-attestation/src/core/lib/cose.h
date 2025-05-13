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
 * Check that buf/len is a valid COSE_Sign1 structure (simple header check).
 * Returns 0 on success, non-zero on failure.
 * Prints a summary to stderr.
 */
int cose_verify_sign1(const uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif // COSE_H