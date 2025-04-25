#include "snp_report.h"
#include <stdlib.h>
#include <string.h>

// Returns a dummy SnpReport for demonstration
struct SnpReport* get_snp_report(size_t* out_len) {
    struct SnpReport* report = (struct SnpReport*)malloc(sizeof(struct SnpReport));
    if (!report) {
        *out_len = 0;
        return NULL;
    }
    memset(report, 0, sizeof(struct SnpReport));
    // Fill with dummy data for demonstration
    report->version = 1;
    memcpy(report->report_data, "dummy_snp_report", 16);
    *out_len = sizeof(struct SnpReport);
    return report;
}