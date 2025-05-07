#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "lib/snp_report.h"
#include "lib/base64.h"
#include "lib/json.h"
#include "lib/cert_chain.h"
#include <openssl/stack.h>
#include <openssl/evp.h>

int main(int argc, char** argv) {

    snp_report_data_t report_data = {0};
    char* report_data_str = NULL;
    char* security_policy_b64 = NULL;
    char* ccf_attestation = NULL;

    // Parse parameters to the script
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--report-data") == 0 && i + 1 < argc) {
            report_data_str = argv[++i];
        }
        else if (strcmp(argv[i], "--security-policy-b64") == 0 && i + 1 < argc) {
            security_policy_b64 = argv[++i];
        }
        else if (argv[i][0] != '-' && ccf_attestation == NULL) {
            ccf_attestation = argv[i];
        }
    }

    // Check for correct usage, otherwise print usage
    if (!security_policy_b64 || !ccf_attestation) {
        fprintf(stderr, "Usage: %s \n", argv[0]);
        fprintf(stderr, "Verify SNP report from CCF attestation\n");
        fprintf(stderr, "Parameters:\n");
        fprintf(stderr, "  [ccf_attestation] \n");
        fprintf(stderr, "  --report-data <string> \n");
        fprintf(stderr, "  --security-policy-b64 <string> \n");
        return 1;
    }

    // Parse report data string into bytes
    memcpy(report_data, report_data_str, fmin(strlen(report_data_str), sizeof(report_data)));

    // Parse SNP report from input JSON
    SnpReport snp_report = {0};
    char* evidence = get_json_field(ccf_attestation, "\"evidence\"");
    uint8_t* snp_report_decoded = base64_decode(evidence, strlen(evidence), NULL);
    free(evidence);
    if (!snp_report_decoded) {
        fprintf(stderr, "Failed to decode or invalid SNP report size\n");
        free(snp_report_decoded);
        return 1;
    }
    memcpy(&snp_report, snp_report_decoded, sizeof(SnpReport));
    free(snp_report_decoded);

    // Parse the endorsements
    char* endorsements = get_json_field(ccf_attestation, "\"endorsements\"");
    char* endorsements_decoded = base64_decode(endorsements, strlen(endorsements), NULL);
    if (!endorsements_decoded) {
        fprintf(stderr, "Failed to decode endorsements\n");
        free(endorsements);
        return 1;
    }
    free(endorsements);

    // Parse the certificate chain
    char* vcekCert = get_json_field(endorsements_decoded, "\"vcekCert\"");
    char* certificateChain = get_json_field(endorsements_decoded, "\"certificateChain\"");
    free(endorsements_decoded);
    cert_chain_t* chain = cert_chain_new();
    if (!chain) {
        fprintf(stderr, "Failed to create certificate chain object\n");
        return 1;
    }
    if (!cert_chain_add_pem(chain, vcekCert)) {
        fprintf(stderr, "Failed to add VCEK certificate to chain\n");
        free(vcekCert);
        return 1;
    }
    free(vcekCert);
    if (!cert_chain_add_pem_chain(chain, certificateChain)) {
        fprintf(stderr, "Failed to append certificate chain\n");
        free(certificateChain);
        return 1;
    }
    free(certificateChain);

    if (verify_snp_report_is_genuine(&snp_report, chain) != 0) {
        cert_chain_free(chain);
        return 1;
    }
    cert_chain_free(chain);

    if (verify_snp_report_has_report_data(&snp_report, &report_data) != 0) {
        return 1;
    }

    if (verify_snp_report_has_security_policy(&snp_report, security_policy_b64) != 0) {
        return 1;
    }

    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nFinal Results:\n");
    fprintf(stderr, "\xE2\x9C\x94 SNP Report comes from genuine AMD hardware\n");
    fprintf(stderr, "\xE2\x9C\x94 SNP Report has the expected report data\n");
    fprintf(stderr, "\xE2\x9C\x94 SNP Report has the expected security policy\n");
    fprintf(stderr, "\nAttestation validation successful\n");
    return 0;
}