#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "lib/snp_report.h"
#include "lib/base64.h"


int main() {

    // Get the SNP report
    SnpReport* snp_report = malloc(sizeof(SnpReport));
    if (!snp_report) {
        fprintf(stderr, "Allocation failure\n");
        return 1;
    }
    snp_report_data_t report_data = {0};
    memset(snp_report, 0, sizeof(SnpReport));
    int ret = get_snp_report(report_data, snp_report);
    if (ret != 0) {
        fprintf(stderr, "Failed to get SNP report\n");
        free(snp_report);
        return 1;
    }

    // Base64 encode the SNP report
    size_t snp_report_b64_len = 0;
    char* snp_report_b64 = base64_encode((const uint8_t*)snp_report, sizeof(SnpReport), &snp_report_b64_len);
    free(snp_report);

    if (!snp_report_b64) {
        fprintf(stderr, "Failed to base64 encode\n");
        free(snp_report_b64);
        return 1;
    }

    // Format the final output JSON
    printf("{\"evidence\": \"%s\"}\n", snp_report_b64);
    free(snp_report_b64);
    return 0;
}