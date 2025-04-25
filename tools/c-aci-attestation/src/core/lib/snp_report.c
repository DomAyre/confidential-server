#include "snp_report.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

/* From sev-snp driver include/uapi/linux/psp-sev-guest.h */
struct SevRequest {
    uint8_t req_msg_type;
    uint8_t rsp_msg_type;
    uint8_t msg_version;
    uint16_t request_len;
    uint64_t request_uaddr;
    uint16_t response_len;
    uint64_t response_uaddr;
    uint32_t error;
};

struct SevGuestRequest {
    uint8_t msg_version;
    uint64_t req_data;
    uint64_t resp_data;
    uint64_t fw_err;
};

static int get_snp_report_sev_guest(uint8_t* report_data, struct SnpReport* out_report) {
    int fd = open("/dev/sev", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

static int get_snp_report_sev(uint8_t* report_data, struct SnpReport* out_report) {
    int fd = open("/dev/sev-guest", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

static int get_snp_report_virtual(struct SnpReport* out_report) {
    memset(out_report, 0, sizeof(struct SnpReport));
    return 0;
}

int get_snp_report(uint8_t* report_data, struct SnpReport* out_report) {
    if (!out_report) return -1;
    if (get_snp_report_sev_guest(report_data, out_report) == 0)
        return 0;
    if (get_snp_report_sev(report_data, out_report) == 0)
        return 0;
    return get_snp_report_virtual(out_report);
}










// static struct SnpReport* get_snp_report_sev(size_t* out_len) {
//     int fd = open("/dev/sev", O_RDWR | O_CLOEXEC);
//     if (fd < 0) return NULL;
//     struct SnpRequest req = {0};
//     struct SnpResponse resp = {0};
//     struct SevRequest payload = {
//         .req_msg_type = SNP_MSG_REPORT_REQ,
//         .rsp_msg_type = SNP_MSG_REPORT_RSP,
//         .msg_version = 1,
//         .request_len = sizeof(req),
//         .request_uaddr = (uint64_t)(void*)&req,
//         .response_len = sizeof(resp),
//         .response_uaddr = (uint64_t)(void*)&resp,
//         .error = 0
//     };
//     if (ioctl(fd, 0xc0305300 /* SEV_SNP_GUEST_MSG_REPORT */, &payload) < 0) {
//         close(fd);
//         return NULL;
//     }
//     close(fd);
//     struct SnpReport* report = (struct SnpReport*)malloc(sizeof(struct SnpReport));
//     if (!report) return NULL;
//     memcpy(report, &resp.report, sizeof(struct SnpReport));
//     *out_len = sizeof(struct SnpReport);
//     return report;
// }

// static struct SnpReport* get_snp_report_sev_guest(size_t* out_len) {
//     int fd = open("/dev/sev-guest", O_RDWR | O_CLOEXEC);
//     if (fd < 0) return NULL;
//     struct SnpRequest req = {0};
//     struct SnpResponse resp = {0};
//     struct SevGuestRequest ioctl_request = {
//         .msg_version = 1,
//         .req_data = (uint64_t)&req,
//         .resp_data = (uint64_t)&resp,
//         .fw_err = 0
//     };
//     if (ioctl(fd, 0xc0185300 /* SNP_GET_REPORT */, &ioctl_request) < 0) {
//         close(fd);
//         return NULL;
//     }
//     close(fd);
//     struct SnpReport* report = (struct SnpReport*)malloc(sizeof(struct SnpReport));
//     if (!report) return NULL;
//     memcpy(report, &resp.report, sizeof(struct SnpReport));
//     *out_len = sizeof(struct SnpReport);
//     return report;
// }

// struct SnpReport* get_snp_report(size_t* out_len) {
//     if (supports_dev_sev()) {
//         return get_snp_report_sev(out_len);
//     } else if (supports_dev_sev_guest()) {
//         return get_snp_report_sev_guest(out_len);
//     }
//     *out_len = 0;
//     return NULL;
// }