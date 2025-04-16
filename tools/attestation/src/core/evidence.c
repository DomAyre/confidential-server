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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "attestation.h"
#include "sev5.h"
#include "sev6.h"

// Helper: base64 encode bytes, allocates output (caller must free)
static int base64_encode_bytes(const uint8_t* decoded, size_t size, char** out_encoded) {
    int required_len = 4 * ((size + 2) / 3) + 1;
    char* buffer = (char*)malloc(required_len);
    if (!buffer) return -1;
    int ret = EVP_EncodeBlock((unsigned char*)buffer, decoded, size);
    if (ret < 0) {
        free(buffer);
        return -1;
    }
    *out_encoded = buffer;
    return 0;
}

int attestation_get_snp_evidence(const char* report_data, char** out_evidence) {
    struct SnpReport report;
    enum SnpType type = attestation_get_snp_type();
    int rc = 0;
    switch (type) {
        case SNP_TYPE_SEV:
            rc = sev5_get_report(report_data, &report);
            break;
        case SNP_TYPE_SEV_GUEST:
            rc = sev6_get_report(report_data, &report);
            break;
        default:
            return -1;
    }
    if (rc != 0) return rc;
    return base64_encode_bytes((const uint8_t*)&report, sizeof(struct SnpReport), out_evidence);
}
