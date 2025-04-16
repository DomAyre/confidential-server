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
#include "attestation.h"

// Print a report in a simple text format
static void print_attestation_report(const struct AttestationReport* report, int fake) {
    printf("report (fake=%d):\n", fake);
    printf("{\n");
    printf("  \"evidence\": \"%s\",\n", report->evidence);
    printf("  \"endorsements\": \"%s\",\n", report->endorsements);
    printf("  \"uvm_endorsements\": \"%s\",\n", report->uvm_endorsements);
    printf("  \"endorsed_tcb\": \"%s\"\n", report->endorsed_tcb);
    printf("}\n");
}

int main(int argc, char* argv[]) {
    const char* report_data = argc > 1 ? argv[1] : "";
    struct AttestationReport report = {0};
    int fake = 0;
    if (attestation_has_snp()) {
        if (attestation_fetch_snp_attestation(report_data, &report) != 0) fake = 1;
    } else {
        fake = 1;
    }
    if (fake) {
        if (attestation_fetch_fake_snp_attestation(&report) != 0) {
            fprintf(stderr, "Failed to get attestation report\n");
            return 1;
        }
    }
    print_attestation_report(&report, fake);
    free(report.evidence);
    free(report.endorsements);
    free(report.uvm_endorsements);
    free(report.endorsed_tcb);
    return 0;
}
