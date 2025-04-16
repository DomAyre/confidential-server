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

int attestation_fetch_snp_attestation(const char* report_data, struct AttestationReport* out_report) {
    if (!attestation_has_snp()) return -1;
    char* evidence = NULL;
    char* endorsements = NULL;
    char* uvm_endorsements = NULL;
    char* endorsed_tcb = NULL;
    if (attestation_get_snp_evidence(report_data, &evidence) != 0) return -1;
    if (attestation_get_snp_endorsements(&endorsements) != 0) { free(evidence); return -1; }
    if (attestation_get_snp_uvm_endorsements(&uvm_endorsements) != 0) { free(evidence); free(endorsements); return -1; }
    if (attestation_get_snp_endorsed_tcb(&endorsed_tcb) != 0) { free(evidence); free(endorsements); free(uvm_endorsements); return -1; }
    out_report->evidence = evidence;
    out_report->endorsements = endorsements;
    out_report->uvm_endorsements = uvm_endorsements;
    out_report->endorsed_tcb = endorsed_tcb;
    return 0;
}
