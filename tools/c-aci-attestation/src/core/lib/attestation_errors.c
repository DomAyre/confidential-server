// attestation_errors.c
// Implementation of error message functions

#include "attestation_errors.h"

const char* attestation_error_message(int error_code) {
    switch (error_code) {
        case ATTESTATION_SUCCESS:
            return "Success";
        case ATTESTATION_ERROR_GENERIC:
            return "Generic error";
        case ATTESTATION_ERROR_INVALID_INPUT:
            return "Invalid input parameters";
        case ATTESTATION_ERROR_MEMORY_ALLOCATION:
            return "Memory allocation failed";
        case ATTESTATION_ERROR_CERT_CHAIN_INVALID:
            return "Certificate chain signature validation failed";
        case ATTESTATION_ERROR_AMD_ROOT_KEY_MISMATCH:
            return "AMD root public key does not match certificate chain";
        case ATTESTATION_ERROR_SNP_SIGNATURE_INVALID:
            return "SNP report signature verification failed";
        case ATTESTATION_ERROR_REPORT_DATA_MISMATCH:
            return "SNP report data does not match expected value";
        case ATTESTATION_ERROR_SECURITY_POLICY_DECODE:
            return "Failed to decode security policy base64";
        case ATTESTATION_ERROR_SECURITY_POLICY_HASH:
            return "Failed to compute security policy hash";
        case ATTESTATION_ERROR_HOST_DATA_MISMATCH:
            return "SNP report host data does not match security policy hash";
        case ATTESTATION_ERROR_ENDORSEMENT_ISSUER_MISMATCH:
            return "Endorsement issuer does not match expected value";
        case ATTESTATION_ERROR_ENDORSEMENT_FEED_MISMATCH:
            return "Endorsement feed does not match expected value";
        case ATTESTATION_ERROR_ENDORSEMENT_SVN_TOO_LOW:
            return "Endorsement SVN does not meet minimum requirement";
        case ATTESTATION_ERROR_ENDORSEMENT_CERT_CHAIN_INVALID:
            return "Endorsement certificate chain is invalid";
        case ATTESTATION_ERROR_ENDORSEMENT_SIGNATURE_INVALID:
            return "COSE_Sign1 signature verification failed";
        case ATTESTATION_ERROR_ENDORSEMENT_LAUNCH_MEASUREMENT_EXTRACT:
            return "Failed to extract launch measurement from endorsement";
        case ATTESTATION_ERROR_ENDORSEMENT_LAUNCH_MEASUREMENT_MISMATCH:
            return "Utility VM endorsement does not match SNP report launch measurement";
        default:
            return "Unknown error";
    }
}