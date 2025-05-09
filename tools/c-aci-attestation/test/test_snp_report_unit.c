// test_snp_report_unit.c - Unit tests for snp_report

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "lib/snp_report.h"

// Test the format_report_data helper
static int test_format(void) {
    const uint8_t data[] = {'A', 'B', 'C'};
    char *out = format_report_data(data, 3);
    if (!out) {
        fprintf(stderr, "[format] NULL output\n");
        return 1;
    }
    const char *expected = "41 42 43\n(ABC)";
    if (strcmp(out, expected) != 0) {
        fprintf(stderr, "[format] FAILED: expected '%s', got '%s'\n", expected, out);
        free(out);
        return 1;
    }
    free(out);
    printf("[PASS] format_report_data\n");
    return 0;
}

// Test get_snp_report error on NULL output pointer
static int test_get_report_null(void) {
    uint8_t report_data[64] = {0};
    int rc = get_snp_report(report_data, NULL);
    if (rc != -1) {
        fprintf(stderr, "[get_null] FAILED: expected -1, got %d\n", rc);
        return 1;
    }
    printf("[PASS] get_snp_report NULL output error\n");
    return 0;
}

// Test get_snp_report virtual fallback
static int test_get_report_virtual(void) {
    uint8_t report_data[64] = {0};
    SnpReport rep;
    int rc = get_snp_report(report_data, &rep);
    if (rc != 0) {
        fprintf(stderr, "[get_report] FAILED: expected 0, got %d\n", rc);
        return 1;
    }
    if (rep.version == 0) {
        fprintf(stderr, "[get_report] FAILED: expected version>0, got %u\n", rep.version);
        return 1;
    }
    printf("[PASS] get_snp_report_virtual version=%u\n", rep.version);
    return 0;
}

int main(void) {
    printf("=== test_snp_report_unit ===\n");
    if (test_format()) return 1;
    if (test_get_report_null()) return 1;
    if (test_get_report_virtual()) return 1;
    printf("All tests passed\n");
    return 0;
}