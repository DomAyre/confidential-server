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

#include "sev6.h"

#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct Request {
    uint8_t msg_version;
    uint64_t req_data;
    uint64_t resp_data;
    uint64_t fw_err;
};

struct RequestWrapper {
    uint8_t data[4000];
};

#define SNP_GUEST_REQ_IOC_TYPE 'S'
#define SNP_GET_REPORT _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x0, struct Request)
#define SNP_GET_DERIVED_KEY _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x1, struct Request)
#define SNP_GET_EXT_REPORT _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x2, struct Request)

// Helper: decode hex string to bytes (reuse from sev5.c)
static size_t hexstr_to_bytes(const char* hexstr, uint8_t* out, size_t maxlen) {
    size_t len = strlen(hexstr);
    size_t outlen = 0;
    for (size_t i = 0; i + 1 < len && outlen < maxlen; i += 2) {
        char byte_str[3] = {hexstr[i], hexstr[i+1], 0};
        out[outlen++] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    return outlen;
}

int sev6_get_report(const char* report_data, struct SnpReport* out_report) {
    if (!report_data || !out_report) return -1;
    struct SnpRequest request = {0};
    size_t num_bytes_to_copy = hexstr_to_bytes(report_data, request.report_data, sizeof(request.report_data));
    (void)num_bytes_to_copy;
    struct RequestWrapper resp_wrapper = {0};
    struct Request payload = {
        .msg_version = 1,
        .req_data = (uint64_t)&request,
        .resp_data = (uint64_t)&resp_wrapper,
        .fw_err = 0
    };
    int sev_guest_file = open("/dev/sev-guest", O_RDWR | O_CLOEXEC);
    if (sev_guest_file < 0) return -1;
    int rc = ioctl(sev_guest_file, SNP_GET_REPORT, &payload);
    close(sev_guest_file);
    if (rc < 0) return -1;
    struct SnpResponse* response = (struct SnpResponse*)&resp_wrapper.data;
    *out_report = response->report;
    return 0;
}
