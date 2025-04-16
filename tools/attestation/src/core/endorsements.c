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
#include <openssl/evp.h>
#include "attestation.h"
#include "utils/host_amd_certs.h"
#include "utils/security_context.h"

// Helper: minimal JSON field extraction (for simple flat JSON)
static char* extract_json_field(const char* json, const char* key) {
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

// Helper: replace all occurrences of a substring in a string (returns malloc'd result)
static char* str_replace(const char* input, const char* search, const char* replace) {
    size_t input_len = strlen(input);
    size_t search_len = strlen(search);
    size_t replace_len = strlen(replace);
    size_t count = 0;
    const char* p = input;
    while ((p = strstr(p, search))) { count++; p += search_len; }
    size_t out_len = input_len + count * (replace_len - search_len) + 1;
    char* out = (char*)malloc(out_len);
    if (!out) return NULL;
    char* dst = out;
    p = input;
    while (*p) {
        if (strncmp(p, search, search_len) == 0) {
            memcpy(dst, replace, replace_len);
            dst += replace_len;
            p += search_len;
        } else {
            *dst++ = *p++;
        }
    }
    *dst = 0;
    return out;
}

int attestation_get_snp_endorsements(char** out_endorsements) {
    struct host_amd_certs certs = {0};
    if (get_host_amd_certs(&certs) != 0) return -1;
    char* json = certs.data;
    char* vcek = extract_json_field(json, "vcekCert");
    char* chain = extract_json_field(json, "certificateChain");
    free(json);
    if (!vcek || !chain) { free(vcek); free(chain); return -1; }
    size_t certs_len = strlen(vcek) + strlen(chain) + 1;
    char* certs_concat = (char*)malloc(certs_len);
    if (!certs_concat) { free(vcek); free(chain); return -1; }
    strcpy(certs_concat, vcek);
    strcat(certs_concat, chain);
    free(vcek);
    free(chain);
    // Remove all double quotes
    char* p = certs_concat, *q = certs_concat;
    while (*p) { if (*p != '"') *q++ = *p; p++; }
    *q = 0;
    // Replace \\n with \n
    char* replaced = str_replace(certs_concat, "\\n", "\n");
    free(certs_concat);
    if (!replaced) return -1;
    // Base64 encode
    size_t len = strlen(replaced);
    int b64_len = 4 * ((len + 2) / 3) + 1;
    char* b64 = (char*)malloc(b64_len);
    if (!b64) { free(replaced); return -1; }
    int outlen = EVP_EncodeBlock((unsigned char*)b64, (const unsigned char*)replaced, len);
    free(replaced);
    if (outlen < 0) { free(b64); return -1; }
    *out_endorsements = b64;
    return 0;
}
