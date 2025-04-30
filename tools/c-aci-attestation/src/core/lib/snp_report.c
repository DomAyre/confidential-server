#include "snp_report.h"
#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdint.h>
#include "embedded_examples.h"
#include "file_utils.h"  // retained for other paths


static int get_snp_report_sev_guest(uint8_t* report_data, SnpReport* out_report) {

    int fd = open("/dev/sev-guest", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;

    // Create SNP Request
    SnpRequest snp_request = {0};
    memcpy(snp_request.report_data, report_data, sizeof(snp_request.report_data));

    // Create SNP Response
    SnpIoctlResponse snp_ioctl_response = {0};
    SnpResponse snp_response = {0};

    // Create IOCTL Payload
    SevGuestIoctlRequest ioctl_request = {
        .msg_version = 1,
        .req_data = (uint64_t)&snp_request,
        .resp_data = (uint64_t)&snp_ioctl_response,
        .fw_err = 0
    };

    // Call IOCTL
    int rc = ioctl(fd, SEV_GUEST_GET_REPORT, &ioctl_request);
    if (rc < 0) {
        fprintf(stderr, "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT\n");
        close(fd);
        return -1;
    }

    // Parse out IOCTL response
    memcpy(&snp_response, &snp_ioctl_response.data, sizeof(SnpResponse));
    memcpy(out_report, &snp_response.report, sizeof(SnpReport));

    close(fd);
    return 0;
}

static int get_snp_report_sev(uint8_t* report_data, SnpReport* out_report) {
    int fd = open("/dev/sev", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;

    // Create SNP Request
    SnpRequest snp_request = {0};
    memcpy(snp_request.report_data, report_data, sizeof(snp_request.report_data));

    // Create SNP Response
    SnpIoctlResponse snp_ioctl_response = {0};
    SnpResponse snp_response = {0};

    // Create IOCTL Payload
    SevIoctlRequest ioctl_request = {
        .req_msg_type = SNP_MSG_REPORT_REQ,
        .rsp_msg_type = SNP_MSG_REPORT_RSP,
        .msg_version = 1,
        .request_len = sizeof(snp_request),
        .request_uaddr = (uint64_t) (void*) &snp_request,
        .response_len = sizeof(snp_ioctl_response),
        .response_uaddr = (uint64_t) (void*) &snp_ioctl_response,
        .error = 0
    };

    // Call IOCTL
    int rc = ioctl(fd, SEV_GUEST_GET_REPORT, &ioctl_request);
    if (rc < 0) {
        fprintf(stderr, "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT\n");
        close(fd);
        return -1;
    }

    // Parse out IOCTL response
    memcpy(&snp_response, &snp_ioctl_response.data, sizeof(SnpResponse));
    memcpy(out_report, &snp_response.report, sizeof(SnpReport));

    close(fd);
    return 0;
}

// Virtual SNP report: decode embedded example blob
static int get_snp_report_virtual(SnpReport* out_report) {
    size_t b64_len = snp_report_b64_end - snp_report_b64_start;
    size_t raw_len = 0;
    uint8_t* raw = base64_decode(
        (const char*)snp_report_b64_start,
        b64_len,
        &raw_len
    );
    if (!raw || raw_len < sizeof(SnpReport)) {
        free(raw);
        return -1;
    }
    memcpy(out_report, raw, sizeof(SnpReport));
    free(raw);
    return 0;
}

int get_snp_report(uint8_t* report_data, SnpReport* out_report) {
    if (!out_report) return -1;
    if (get_snp_report_sev_guest(report_data, out_report) == 0) {
        return 0;
    }
    if (get_snp_report_sev(report_data, out_report) == 0)
        return 0;
    return get_snp_report_virtual(out_report);
}
