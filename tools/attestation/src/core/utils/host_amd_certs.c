/*
 * Portions Copyright (c) Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "host_amd_certs.h"
#include "security_context.h"

// Helper: base64 decode (allocates output, caller must free)
static unsigned char* base64_decode(const char* b64, size_t* out_len) {
    size_t len = strlen(b64);
    size_t max_decoded = 3 * len / 4;
    unsigned char* buf = (unsigned char*)malloc(max_decoded + 1);
    if (!buf) return NULL;
    int n = EVP_DecodeBlock(buf, (const unsigned char*)b64, len);
    if (n < 0) { free(buf); return NULL; }
    if (out_len) *out_len = n;
    return buf;
}

// Reads and decodes the host AMD certs JSON (caller must free result)
char* get_host_amd_certs_json(size_t* out_len) {
    size_t b64_len;
    char* b64 = NULL;
    if (get_security_context_file("/host-amd-cert-base64", &b64, &b64_len) != 0) return NULL;
    size_t decoded_len;
    unsigned char* decoded = base64_decode(b64, &decoded_len);
    free(b64);
    if (!decoded) return NULL;
    char* json = (char*)malloc(decoded_len + 1);
    if (!json) { free(decoded); return NULL; }
    memcpy(json, decoded, decoded_len);
    json[decoded_len] = 0;
    free(decoded);
    if (out_len) *out_len = decoded_len;
    return json;
}

// Stub implementation for get_host_amd_certs to resolve linker errors
int get_host_amd_certs(struct host_amd_certs *certs) {
    if (certs) {
        certs->data = NULL;
        certs->length = 0;
    }
    return -1; // Indicate error or unimplemented
}
