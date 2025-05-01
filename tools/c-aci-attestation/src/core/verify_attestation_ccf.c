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

// Trusted root public key PEM (insert the actual PEM here)
const char* cert_chain_trusted_root_pubkey_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsV\n"
    "mD7FktuotWwX1fNgW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU\n"
    "0V5tkKiU1EesNFta1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S\n"
    "1ju8X93+6dxDUrG2SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI5\n"
    "2Naz5m2B+O+vjsC060d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3K\n"
    "FYXP59XmJgtcog05gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd\n"
    "/y8KxX7jksTEzAOgbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBk\n"
    "gnlENEWx1UcbQQrs+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V\n"
    "9TJQqnN3Q53kt5viQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnq\n"
    "z55I0u33wh4r0ZNQeTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+Og\n"
    "pCCoMNit2uLo9M18fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXo\n"
    "QPHfbkH0CyPfhl1jWhJFZasCAwEAAQ==\n"
    "-----END PUBLIC KEY-----\n";

int main(int argc, char** argv) {

    snp_report_data_t report_data = {0};
    char* security_policy_b64 = NULL;
    char* ccf_attestation = NULL;

    // Parse options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--report-data") == 0 && i + 1 < argc) {
            // Copy the report data string into the report_data buffer
            const char* input = argv[++i];
            size_t input_len = strlen(input);
            size_t copy_len = input_len < sizeof(report_data) ? input_len : sizeof(report_data);
            memcpy(report_data, input, copy_len);
        } else if (strcmp(argv[i], "--security-policy-b64") == 0 && i + 1 < argc) {
            security_policy_b64 = argv[++i];
        } else if (argv[i][0] != '-' && ccf_attestation == NULL) {
            // First positional argument (not an option)
            ccf_attestation = argv[i];
        }
    }

    if (!security_policy_b64 || !ccf_attestation) {
        fprintf(stderr, "Usage: %s --report-data <string> --security-policy-b64 <string> [ccf_attestation]\n", argv[0]);
        return 1;
    }

    char* evidence = get_json_field(ccf_attestation, "\"evidence\"");
    char* endorsements = get_json_field(ccf_attestation, "\"endorsements\"");

    SnpReport snp_report = {0};
    size_t snp_report_decoded_len = 0;
    uint8_t* snp_report_decoded = base64_decode(evidence, strlen(evidence), &snp_report_decoded_len);
    if (!snp_report_decoded || snp_report_decoded_len < sizeof(SnpReport)) {
        fprintf(stderr, "Failed to decode or invalid SNP report size\n");
        free(snp_report_decoded);
        free(evidence);
        free(endorsements);
        return 1;
    }
    memcpy(&snp_report, snp_report_decoded, sizeof(SnpReport));
    free(snp_report_decoded);

    // Check the report data matches
    if (verify_snp_report_has_report_data(&snp_report, &report_data) != 0) {
        free(evidence);
        free(endorsements);
        return 1;
    }

    // Parse the endorsements
    char* endorsements_decoded = base64_decode(endorsements, strlen(endorsements), NULL);
    if (!endorsements_decoded) {
        fprintf(stderr, "Failed to decode endorsements\n");
        free(evidence);
        free(endorsements);
        return 1;
    }
    char* vcekCert = get_json_field(endorsements_decoded, "\"vcekCert\"");
    char* certificateChain = get_json_field(endorsements_decoded, "\"certificateChain\"");

    {
        cert_chain_t* chain = cert_chain_new();
        if (!chain) {
            fprintf(stderr, "Failed to create certificate chain object\n");
        } else {
            // Add VCEK certificate
            if (!cert_chain_add_pem(chain, vcekCert)) {
                fprintf(stderr, "Failed to add VCEK certificate to chain\n");
            }
            // Append the rest of the chain
            if (!cert_chain_add_pem_chain(chain, certificateChain)) {
                fprintf(stderr, "Failed to append certificate chain\n");
            }

            if (verify_snp_report_is_genuine(&snp_report, chain) != 0) {
                free(evidence);
                free(endorsements_decoded);
                free(vcekCert);
                free(certificateChain);
                free(evidence);
                free(endorsements);
                return 1;
            }
            cert_chain_free(chain);
        }
    }

    if (verify_snp_report_has_security_policy(&snp_report, security_policy_b64) != 0) {
        free(evidence);
        free(endorsements_decoded);
        free(vcekCert);
        free(certificateChain);
        return 1;
    }

    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nFinal Results:\n");
    fprintf(stderr, "\xE2\x9C\x94 SNP Report comes from genuine AMD hardware\n");
    fprintf(stderr, "\xE2\x9C\x94 SNP Report has the expected report data\n");
    fprintf(stderr, "\xE2\x9C\x94 SNP Report has the expected security policy\n");
    fprintf(stderr, "\nAttestation validation successful\n");

    // Cleanup
    free(endorsements_decoded);
    free(vcekCert);
    free(certificateChain);
    free(evidence);
    free(endorsements);
    return 0;
}