/*
 * Simple implementation of COSE_Sign1 structure check.
 */
#include "cose.h"
#include "json.h"
#include <stdio.h>
#include <stdlib.h>
#include "t_cose/t_cose_sign1_verify.h"
#include "qcbor/qcbor.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"


char* get_cose_payload(const uint8_t* buf, size_t len) {

    /* Basic input validation */
    if (buf == NULL || len == 0) {
        fprintf(stderr, "✘ uvm_endorsements buffer is null or empty\n");
        return NULL;
    }

    /* Initialise QCBOR decoder */
    UsefulBufC msg = { .ptr = buf, .len = len };
    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, msg, QCBOR_DECODE_MODE_NORMAL);

    /* Iterate through all top-level CBOR items in the buffer */
    QCBORDecodeContext seq_ctx;
    QCBORDecode_Init(&seq_ctx, msg, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    int found_valid = 0;
    while (1) {
        QCBORDecode_VGetNext(&seq_ctx, &item);
        if (item.uDataType == QCBOR_TYPE_NONE) {
            break;
        }
        if (item.uTags[0] == 18 && item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 4) {
            found_valid = 1;
        }
    }

    QCBORError err = QCBORDecode_Finish(&seq_ctx);
    if (!found_valid) {
        fprintf(stderr, "✘ No valid COSE_Sign1 structure found in buffer\n");
        return NULL;
    }

    // Extract and print the payload from the COSE_Sign1 structure
    QCBORDecodeContext payload_ctx;
    QCBORDecode_Init(&payload_ctx, msg, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem payload_item;
    char* payload = NULL;
    while (1) {
        QCBORDecode_VGetNext(&payload_ctx, &payload_item);
        if (payload_item.uDataType == QCBOR_TYPE_NONE) {
            break;
        }
        if (payload_item.uTags[0] == 18 && payload_item.uDataType == QCBOR_TYPE_ARRAY && payload_item.val.uCount == 4) {
            // Enter the array and get to the payload (3rd element)
            QCBORDecode_EnterArray(&payload_ctx, NULL);
            QCBORItem tmp;
            QCBORDecode_GetNext(&payload_ctx, &tmp); // protected headers
            QCBORDecode_GetNext(&payload_ctx, &tmp); // unprotected headers
            QCBORDecode_GetNext(&payload_ctx, &tmp); // payload
            if (tmp.uDataType == QCBOR_TYPE_BYTE_STRING) {
                payload = malloc(tmp.val.string.len + 1);
                memcpy(payload, tmp.val.string.ptr, tmp.val.string.len);
                payload[tmp.val.string.len] = '\0';
            } else {
                fprintf(stderr, "✘ COSE_Sign1 payload is not a byte string\n");
            }
            QCBORDecode_ExitArray(&payload_ctx);
            break;
        }
    }

    if (err != QCBOR_ERR_NO_MORE_ITEMS && err != QCBOR_SUCCESS) {
        fprintf(stderr, "✘ QCBOR decoding failed with error %d\n", err);
        return NULL;
    }

    return payload;
}