/*
 * Simple implementation of COSE_Sign1 structure check.
 */
#include "cose.h"
#include <stdio.h>
#include "t_cose/t_cose_sign1_verify.h"


int cose_verify_sign1(const uint8_t* buf, size_t len) {
    /* Need at least a CBOR tag (1 byte) and array header (1 byte) */
    if (len < 2) {
        fprintf(stderr, "✘ uvm_endorsements too small to be COSE_Sign1\n");
        return 1;
    }
    /* COSE_Sign1 uses CBOR tag 18 (0xd2) */
    if ((uint8_t)buf[0] != 0xd2) {
        fprintf(stderr, "✘ Invalid COSE tag: expected 0xd2, got 0x%02x\n", (uint8_t)buf[0]);
        return 1;
    }
    /* Next byte is array header for 4 elements: major type 4, ai=4 -> 0x84 */
    uint8_t hdr = (uint8_t)buf[1];
    if ((hdr & 0xE0) != 0x80 || (hdr & 0x1F) != 4) {
        fprintf(stderr, "✘ Invalid COSE_Sign1 array header: 0x%02x\n", hdr);
        return 1;
    }
    fprintf(stderr, "✔ uvm_endorsements is valid COSE_Sign1 structure\n");

    return 0;
}