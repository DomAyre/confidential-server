#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include "lib/snp_report.h"
#include "lib/cert_chain.h"
#include "lib/base64.h"
#include "lib/sha256.h"
#include "lib/hex.h"

const char* amd_public_key_pem =
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


int verify_snp_report_is_genuine(SnpReport* snp_report, cert_chain_t* cert_chain) {
    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nVerifying SNP report is signed by a chain of certs going to AMD's root of trust\n");
    fprintf(stderr, "\nAMD's public key:\n%s\n", amd_public_key_pem);

    // 1. Check the public key signs the root of the chain
    EVP_PKEY* amd_public_key = pubkey_from_pem(amd_public_key_pem);
    int root_valid = cert_chain_validate_root(cert_chain, amd_public_key);
    if (root_valid) {
        fprintf(stderr, "✔ AMD's public key signed the root of the chain\n");
    } else {
        fprintf(stderr, "✘ AMD's public key did not sign the root of the chain\n");
        return 1;
    }
    pubkey_free(amd_public_key);

    // 2. Check the certs in the chain sign each other as expected
    STACK_OF(X509)* stack = cert_chain_get_stack(cert_chain);
    size_t num = stack ? sk_X509_num(stack) : 0;
    if (num != 3) {
        fprintf(stderr, "✘ Expected 3 certificates in the chain, got %zu\n", num);
        return 1;
    }
    int cert_chain_valid = cert_chain_validate(cert_chain);
    if (cert_chain_valid) {
        fprintf(stderr, "✔ Certificates signature chain valid\n");
    } else {
        fprintf(stderr, "✘ Certificates signature chain invalid\n");
        return 1;
    }

    // 3. Extract VCEK public key (leaf)
    X509* vcek_cert = sk_X509_value(stack, 0);
    if (!vcek_cert) {
        fprintf(stderr, "✘ Could not get VCEK certificate from chain\n");
        return 1;
    }
    EVP_PKEY* vcek_pubkey = X509_get_pubkey(vcek_cert);
    if (!vcek_pubkey) {
        fprintf(stderr, "✘ Could not extract VCEK public key from certificate\n");
        return 1;
    }

    // 4. Compute SHA-384 on report up to, but not including, signature
    size_t tbs_len = offsetof(SnpReport, signature);  // structure layout, not including signature field
    unsigned char digest[48];  // SHA-384 output is 48 bytes
    unsigned int digest_len = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "✘ Failed to allocate digest context\n");
        EVP_PKEY_free(vcek_pubkey);
        return 1;
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, snp_report, tbs_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
        fprintf(stderr, "✘ Error in report hash calculation\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(vcek_pubkey);
        return 1;
    }
    EVP_MD_CTX_free(mdctx);
    if (digest_len != 48) {
        fprintf(stderr, "✘ SHA-384 output length incorrect\n");
        EVP_PKEY_free(vcek_pubkey);
        return 1;
    }

    // 5. Prepare ECDSA_SIG from r,s in snp_report->signature (each 72 bytes, padded/left aligned)
    const Signature* sig = &snp_report->signature;
    // Convert r and s to BIGNUM
    BIGNUM* r = BN_lebin2bn(sig->r, 72, NULL);
    BIGNUM* s = BN_lebin2bn(sig->s, 72, NULL);
    if (!r || !s) {
        fprintf(stderr, "✘ Failed to extract r,s from signature\n");
        EVP_PKEY_free(vcek_pubkey);
        if(r) BN_free(r);
        if(s) BN_free(s);
        return 1;
    }
    ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig) {
        fprintf(stderr, "✘ Failed to allocate ECDSA_SIG\n");
        BN_free(r);
        BN_free(s);
        EVP_PKEY_free(vcek_pubkey);
        return 1;
    }
    if (ECDSA_SIG_set0(ecdsa_sig, r, s) != 1) {
        fprintf(stderr, "✘ Failed to set r and s in ECDSA_SIG\n");
        ECDSA_SIG_free(ecdsa_sig);
        EVP_PKEY_free(vcek_pubkey);
        return 1;
    }

    // 6. Actually verify the signature using VCEK public key
    // Wrap OpenSSL 3.0 deprecated functions
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    // Get EC_KEY from EVP_PKEY
    EC_KEY* ec_key = EVP_PKEY_get1_EC_KEY(vcek_pubkey);
#pragma GCC diagnostic pop
    if (!ec_key) {
        fprintf(stderr, "✘ Could not extract EC_KEY from VCEK public key\n");
        ECDSA_SIG_free(ecdsa_sig);
        EVP_PKEY_free(vcek_pubkey);
        return 1;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    int verify_ok = ECDSA_do_verify(digest, 48, ecdsa_sig, ec_key);
#pragma GCC diagnostic pop

    ECDSA_SIG_free(ecdsa_sig);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    EC_KEY_free(ec_key);
#pragma GCC diagnostic pop
    EVP_PKEY_free(vcek_pubkey);

    if (verify_ok == 1) {
        fprintf(stderr, "✔ SNP Report is from genuine AMD hardware\n");
        return 0;
    } else {
        fprintf(stderr, "✘ SNP Report signature did NOT validate under VCEK public key\n");
        return 1;
    }
}


int verify_snp_report_has_report_data(SnpReport* snp_report, snp_report_data_t* report_data) {
    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nVerifying SNP report has the expected report data\n");

    char* actual = format_report_data(snp_report->report_data,
                                      sizeof(snp_report->report_data));
    fprintf(stderr, "\nActual: \n%s\n", actual ? actual : "(format error)");
    free(actual);

    char* expect = format_report_data(*report_data,
                                     sizeof(*report_data));
    fprintf(stderr, "\nExpected: \n%s\n", expect ? expect : "(format error)");
    free(expect);

    if (memcmp(snp_report->report_data, report_data, sizeof(snp_report_data_t)) == 0) {
        fprintf(stderr, "\n✔ Report data matches\n");
        return 0;
    } else {
        fprintf(stderr, "\n✘ Report data does not match\n");
        return 1;
    }
}


int verify_snp_report_has_security_policy(SnpReport* snp_report, const char* security_policy_b64) {
    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nVerifying SNP report's host_data field matches the expected security policy\n");

    size_t policy_len = 0;
    uint8_t* security_policy = base64_decode(security_policy_b64, strlen(security_policy_b64), &policy_len);
    if (!security_policy) {
        fprintf(stderr, "Failed to decode security policy\n");
        return 1;
    }

    fprintf(stderr, "\nExpected Security Policy: \n%s\n", security_policy);

    uint8_t* policy_hash = sha256(security_policy, policy_len);
    free(security_policy);
    if (!policy_hash) {
        fprintf(stderr, "Failed to compute SHA-256 hash of security policy\n");
        return 1;
    }

    fprintf(stderr, "\nSecurity Policy SHA256: \n%s\n", hex_encode(policy_hash, sizeof(snp_report->host_data), NULL));
    fprintf(stderr, "\nSNP Report Host Data: \n%s\n", hex_encode(snp_report->host_data, sizeof(snp_report->host_data), NULL));

    if (memcmp(policy_hash, snp_report->host_data, sizeof(snp_report->host_data)) == 0) {
        fprintf(stderr, "\n✔ SNP report's host_data matches the security policy hash\n");
        free(policy_hash);
        return 0;
    } else {
        fprintf(stderr, "\n✘ SNP report's host_data does not match security policy hash\n");
        free(policy_hash);
        return 1;
    }
}

int verify_host_vm_build() {
    fprintf(stderr, "\n----------------------------------------------------\n");
    fprintf(stderr, "\nVerifying that the Host VM build is trusted\n");
    fprintf(stderr, "\nEventually, this will be done by making builds reproducable, and comparing a digest of the VM image. ");
    fprintf(stderr, "For now, we check that the digest of the build is endorsed by Microsoft\n");

    fprintf(stderr, "\n- To be implemented\n");
    return 0;
}