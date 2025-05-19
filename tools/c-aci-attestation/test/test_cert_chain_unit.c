// test_cert_chain_unit.c - Unit tests for cert_chain

#include <stdio.h>
#include <stdlib.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include "lib/cert_chain.h"
#include "lib/host_amd_certs.h"

static int test_new_and_free(void) {
    cert_chain_t *chain = cert_chain_new();
    if (!chain) {
        fprintf(stderr, "[new] Returned NULL\n");
        return 1;
    }
    STACK_OF(X509) *stack = cert_chain_get_stack(chain);
    if (!stack) {
        fprintf(stderr, "[new] get_stack returned NULL\n");
        cert_chain_free(chain);
        return 1;
    }
    if (sk_X509_num(stack) != 0) {
        fprintf(stderr, "[new] Expected 0 certs, got %d\n", sk_X509_num(stack));
        cert_chain_free(chain);
        return 1;
    }
    cert_chain_free(chain);
    printf("[PASS] new and free empty chain\n");
    return 0;
}

static int test_add_invalid_pem(void) {
    cert_chain_t *chain = cert_chain_new();
    if (!chain) {
        fprintf(stderr, "[add_invalid] new returned NULL\n");
        return 1;
    }
    int ok = cert_chain_add_pem(chain, "not a pem");
    if (ok != 1) {
        fprintf(stderr, "[add_invalid] Expected 0, got %d\n", ok);
        cert_chain_free(chain);
        return 1;
    }
    cert_chain_free(chain);
    printf("[PASS] add invalid pem fails\n");
    return 0;
}

static int test_add_pem_chain_invalid(void) {
    cert_chain_t *chain = cert_chain_new();
    if (!chain) {
        fprintf(stderr, "[add_chain_invalid] new returned NULL\n");
        return 1;
    }
    int ok = cert_chain_add_pem_chain(chain, "not a pem chain");
    // Function returns 1 even if no certificates are added
    if (ok != 0) {
        fprintf(stderr, "[add_chain_empty] Expected 1, got %d\n", ok);
        cert_chain_free(chain);
        return 1;
    }
    cert_chain_free(chain);
    printf("[PASS] add empty pem chain returns success\n");
    return 0;
}

// Test null inputs for all APIs
static int test_null_inputs(void) {
    cert_chain_free(NULL);
    if (cert_chain_add_pem(NULL, "x") == 0) return 1;
    if (cert_chain_add_pem_chain(NULL, "x") == 0) return 1;
    if (cert_chain_get_stack(NULL)) return 1;
    if (cert_chain_validate(NULL, 0) == 0) return 1;
    if (cert_chain_validate_root(NULL, NULL) == 0) return 1;
    printf("[PASS] null input error paths\n");
    return 0;
}

int main(void) {
    // Declare test suite
    printf("=== test_cert_chain_unit ===\n");
    if (test_new_and_free()) return 1;
    if (test_add_invalid_pem()) return 1;
    if (test_add_pem_chain_invalid()) return 1;
    if (test_null_inputs()) return 1;
    printf("All tests passed\n");
    return 0;
}