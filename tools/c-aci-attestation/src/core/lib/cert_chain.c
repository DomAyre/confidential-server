#include "cert_chain.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/stack.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
// Helper to unescape JSON-style escape sequences for PEM strings.
// Converts "\\n" to newline, "\\r" to CR, "\\\\" to "\\", others as-is.
static char* unescape_json(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char* out = malloc(len + 1);
    if (!out) return NULL;
    char* d = out;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '\\' && i + 1 < len) {
            char next = s[i+1];
            if (next == 'n') {
                *d++ = '\n';
                i++;
            } else if (next == 'r') {
                *d++ = '\r';
                i++;
            } else if (next == '\\') {
                *d++ = '\\';
                i++;
            } else {
                *d++ = s[i];
            }
        } else {
            *d++ = s[i];
        }
    }
    *d = '\0';
    return out;
}

// cert_chain.c - Wrapper around OpenSSL to create certificate chains from PEM strings.

struct cert_chain {
    STACK_OF(X509)* stack;
};

cert_chain_t* cert_chain_create(const char* const* pem_certs, size_t count) {
    if (!pem_certs || count == 0) {
        return NULL;
    }
    cert_chain_t* chain = malloc(sizeof(*chain));
    if (!chain) return NULL;
    chain->stack = sk_X509_new_null();
    if (!chain->stack) {
        free(chain);
        return NULL;
    }
    for (size_t i = 0; i < count; i++) {
        const char* pem = pem_certs[i];
        if (!pem) continue;
        BIO* bio = BIO_new_mem_buf(pem, -1);
        if (!bio) {
            cert_chain_free(chain);
            return NULL;
        }
        X509* cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
        BIO_free(bio);
        if (!cert) {
            cert_chain_free(chain);
            return NULL;
        }
        if (!sk_X509_push(chain->stack, cert)) {
            X509_free(cert);
            cert_chain_free(chain);
            return NULL;
        }
    }
    return chain;
}

void cert_chain_free(cert_chain_t* chain) {
    if (!chain) return;
    if (chain->stack) {
        while (sk_X509_num(chain->stack) > 0) {
            X509* cert = sk_X509_pop(chain->stack);
            X509_free(cert);
        }
        sk_X509_free(chain->stack);
    }
    free(chain);
}

STACK_OF(X509)* cert_chain_get_stack(const cert_chain_t* chain) {
    if (!chain) return NULL;
    return chain->stack;
}
// Parse a primary PEM and an additional concatenated PEM chain into a cert_chain_t
cert_chain_t* cert_chain_create_from_pem_chain(const char* first_pem,
                                              const char* pem_chain) {
    // Unescape JSON-encoded PEM strings
    char* upem0 = unescape_json(first_pem);
    char* upem_chain = unescape_json(pem_chain);
    if (!upem0 || !upem_chain) {
        free(upem0);
        free(upem_chain);
        return NULL;
    }
    const char* begin_marker = "-----BEGIN CERTIFICATE-----";
    size_t begin_len = strlen(begin_marker);
    // Count PEM blocks in upem_chain
    size_t count = 1;
    const char* p = upem_chain;
    while ((p = strstr(p, begin_marker))) {
        count++;
        p += begin_len;
    }
    // Allocate array of PEM pointers
    char** arr = malloc(sizeof(*arr) * count);
    if (!arr) {
        free(upem0);
        free(upem_chain);
        return NULL;
    }
    // First certificate
    arr[0] = upem0;
    // Extract each PEM block
    p = upem_chain;
    size_t idx = 1;
    while ((p = strstr(p, begin_marker)) && idx < count) {
        const char* start = p;
        const char* end = strstr(start, "-----END CERTIFICATE-----");
        if (!end) break;
        end += strlen("-----END CERTIFICATE-----");
        size_t len = end - start;
        char* cert = malloc(len + 1);
        if (!cert) break;
        memcpy(cert, start, len);
        cert[len] = '\0';
        arr[idx++] = cert;
        p = end;
    }
    // Build chain
    cert_chain_t* chain = cert_chain_create((const char* const*)arr, idx);
    // Free temporary buffers
    for (size_t i = 0; i < idx; i++) {
        free(arr[i]);
    }
    free(arr);
    free(upem_chain);
    return chain;
}
// Creates a new, empty certificate chain. Returns NULL on failure.
// Caller must free with cert_chain_free().
cert_chain_t* cert_chain_new(void) {
    cert_chain_t* chain = malloc(sizeof(*chain));
    if (!chain) return NULL;
    chain->stack = sk_X509_new_null();
    if (!chain->stack) {
        free(chain);
        return NULL;
    }
    return chain;
}
// Adds a single PEM certificate (possibly JSON-escaped) to an existing chain.
// Returns 1 on success, 0 on failure.
int cert_chain_add_pem(cert_chain_t* chain, const char* pem) {
    if (!chain || !pem) return 0;
    char* upem = unescape_json(pem);
    if (!upem) return 0;
    BIO* bio = BIO_new_mem_buf(upem, -1);
    if (!bio) {
        free(upem);
        return 0;
    }
    X509* cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    free(upem);
    if (!cert) return 0;
    if (!sk_X509_push(chain->stack, cert)) {
        X509_free(cert);
        return 0;
    }
    return 1;
}
// Parses one or more PEM certificates concatenated (possibly JSON-escaped)
// and adds them to the existing chain. Returns 1 if all were added successfully, 0 otherwise.
int cert_chain_add_pem_chain(cert_chain_t* chain, const char* pem_chain) {
    if (!chain || !pem_chain) return 0;
    char* upem_chain = unescape_json(pem_chain);
    if (!upem_chain) return 0;
    const char* begin_marker = "-----BEGIN CERTIFICATE-----";
    const char* p = upem_chain;
    int ok = 1;
    while ((p = strstr(p, begin_marker))) {
        const char* start = p;
        const char* end = strstr(start, "-----END CERTIFICATE-----");
        if (!end) { ok = 0; break; }
        end += strlen("-----END CERTIFICATE-----");
        const char* q = end;
        while (*q == '\r' || *q == '\n') q++;
        size_t len = q - start;
        char* cert = malloc(len + 1);
        if (!cert) { ok = 0; break; }
        memcpy(cert, start, len);
        cert[len] = '\0';
        if (!cert_chain_add_pem(chain, cert)) ok = 0;
        free(cert);
        p = q;
    }
    free(upem_chain);
    return ok;
}
// Validates that each certificate in the chain is signed by the next certificate.
// The last certificate is expected to be self-signed.
// Returns 1 on successful verification of all signatures, 0 otherwise.
int cert_chain_validate(const cert_chain_t* chain) {
    if (!chain) return 0;
    STACK_OF(X509)* stack = cert_chain_get_stack(chain);
    if (!stack) return 0;
    int num = sk_X509_num(stack);
    if (num <= 0) return 0;
    // Verify each cert is signed by its issuer (next cert in the stack)
    for (int i = 0; i < num - 1; i++) {
        X509* cert = sk_X509_value(stack, i);
        X509* issuer = sk_X509_value(stack, i + 1);
        EVP_PKEY* key = X509_get_pubkey(issuer);
        if (!key) return 0;
        int ok = X509_verify(cert, key);
        EVP_PKEY_free(key);
        if (ok <= 0) return 0;
    }
    // Verify the last certificate is self-signed
    X509* last = sk_X509_value(stack, num - 1);
    EVP_PKEY* root_key = X509_get_pubkey(last);
    if (!root_key) return 0;
    int root_ok = X509_verify(last, root_key);
    EVP_PKEY_free(root_key);
    return (root_ok > 0);
}
// Loads a public key from a PEM-formatted string (JSON-escaped allowed).
// Returns an EVP_PKEY* on success, or NULL on failure. Caller must free with pubkey_free().
EVP_PKEY* pubkey_from_pem(const char* pem) {
    if (!pem) return NULL;
    // Unescape JSON-encoded PEM
    char* upem = unescape_json(pem);
    if (!upem) return NULL;
    BIO* bio = BIO_new_mem_buf(upem, -1);
    if (!bio) {
        free(upem);
        return NULL;
    }
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, NULL, 0, NULL);
    BIO_free(bio);
    free(upem);
    return key;
}
// Frees a public key loaded by pubkey_from_pem(). Safe to call with NULL.
void pubkey_free(EVP_PKEY* key) {
    if (key) EVP_PKEY_free(key);
}
// Validates that the root certificate in the chain is signed by the provided public key.
// Returns 1 if the root cert is validly signed, 0 otherwise.
int cert_chain_validate_root(const cert_chain_t* chain, EVP_PKEY* trusted_root_pubkey) {
    if (!chain || !trusted_root_pubkey) return 0;
    STACK_OF(X509)* stack = cert_chain_get_stack(chain);
    if (!stack) return 0;
    int num = sk_X509_num(stack);
    if (num <= 0) return 0;
    X509* root = sk_X509_value(stack, num - 1);
    if (!root) return 0;
    // Verify root certificate signature with provided public key
    int ok = X509_verify(root, trusted_root_pubkey);
    return (ok > 0);
}