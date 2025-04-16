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

#include "sev5.h"

#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* linux kernel 5.15.* versions of the ioctls that talk to the PSP */

/* From sev-snp driver include/uapi/linux/psp-sev-guest.h */
struct Request {
    uint8_t req_msg_type;
    uint8_t rsp_msg_type;
    uint8_t msg_version;
    uint16_t request_len;
    uint64_t request_uaddr;
    uint16_t response_len;
    uint64_t response_uaddr;
    uint32_t error;
};

#define SEV_GUEST_IOC_TYPE 'S'
#define SEV_SNP_GUEST_MSG_REQUEST _IOWR(SEV_GUEST_IOC_TYPE, 0x0, struct Request)
#define SEV_SNP_GUEST_MSG_REPORT _IOWR(SEV_GUEST_IOC_TYPE, 0x1, struct Request)
#define SEV_SNP_GUEST_MSG_KEY _IOWR(SEV_GUEST_IOC_TYPE, 0x2, struct Request)

// Helper: decode hex string to bytes
static size_t hexstr_to_bytes(const char* hexstr, uint8_t* out, size_t maxlen) {
    size_t len = strlen(hexstr);
    size_t outlen = 0;
    for (size_t i = 0; i + 1 < len && outlen < maxlen; i += 2) {
        char byte_str[3] = {hexstr[i], hexstr[i+1], 0};
        out[outlen++] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    return outlen;
}

int sev5_get_report(const char* report_data, struct SnpReport* out_report) {
    if (!report_data || !out_report) return -1;
    struct SnpRequest request = {0};
    size_t num_bytes_to_copy = hexstr_to_bytes(report_data, request.report_data, sizeof(request.report_data));
    (void)num_bytes_to_copy; // Not strictly needed, but could check for errors
    struct SnpResponse response = {0};
    struct Request payload = {
        .req_msg_type = SNP_MSG_REPORT_REQ,
        .rsp_msg_type = SNP_MSG_REPORT_RSP,
        .msg_version = 1,
        .request_len = sizeof(request),
        .request_uaddr = (uint64_t)(void*)&request,
        .response_len = sizeof(response),
        .response_uaddr = (uint64_t)(void*)&response,
        .error = 0
    };
    int sev_file = open("/dev/sev", O_RDWR | O_CLOEXEC);
    if (sev_file < 0) return -1;
    int rc = ioctl(sev_file, SEV_SNP_GUEST_MSG_REPORT, &payload);
    close(sev_file);
    if (rc < 0) return -1;
    *out_report = response.report;
    return 0;
}
