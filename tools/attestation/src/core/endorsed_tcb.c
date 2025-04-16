/*
 * Portions Copyright (c) Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
#include <stdbool.h>
#include "attestation.h"
#include "utils/host_amd_certs.h"
#include "utils/security_context.h"

// Helper: minimal JSON field extraction (for simple flat JSON)
static char* extract_json_field(const char* json, const char* key) {
    // This is a minimal, non-robust implementation for demo purposes only
    char* found = strstr(json, key);
    if (!found) return NULL;
    found = strchr(found, ':');
    if (!found) return NULL;
    found++;
    while (*found == ' ' || *found == '"') found++;
    char* end = strchr(found, '"');
    if (!end) end = strchr(found, ',');
    if (!end) end = strchr(found, '}');
    if (!end) return NULL;
    size_t len = end - found;
    char* out = (char*)malloc(len + 1);
    if (!out) return NULL;
    strncpy(out, found, len);
    out[len] = 0;
    return out;
}

int attestation_get_snp_endorsed_tcb(char** out_endorsed_tcb) {
    struct host_amd_certs certs = {0};
    if (get_host_amd_certs(&certs) != 0) return -1;
    char* json = certs.data;
    char* tcbm = extract_json_field(json, "tcbm");
    free(json);
    if (!tcbm) return -1;
    // Reverse endianness (pairs of hex digits)
    size_t len = strlen(tcbm);
    char* reversed = (char*)malloc(len + 1);
    if (!reversed) { free(tcbm); return -1; }
    for (size_t i = 0; i < len; i += 2) {
        reversed[i] = tcbm[len - i - 2];
        reversed[i+1] = tcbm[len - i - 1];
    }
    reversed[len] = 0;
    free(tcbm);
    *out_endorsed_tcb = reversed;
    return 0;
}
