#include <stddef.h>
#include <openssl/x509.h>

#ifndef CERT_CHAIN_H
#define CERT_CHAIN_H

#ifdef __cplusplus
extern "C" {
#endif

// Opaque certificate chain structure
typedef struct cert_chain cert_chain_t;

// Creates a certificate chain from an array of PEM-formatted null-terminated strings.
// pem_certs: array of PEM certificate strings.
// count: number of certificates in the array.
// Returns a pointer to a cert_chain_t on success, or NULL on failure. Caller must free with cert_chain_free().
cert_chain_t* cert_chain_create(const char* const* pem_certs, size_t count);

// Frees a certificate chain created by cert_chain_create().
// Safe to call with NULL.
void cert_chain_free(cert_chain_t* chain);

// Returns the underlying OpenSSL STACK_OF(X509)* representing the certificate chain.
// Caller must not modify or free the returned stack. Returns NULL if chain is NULL.
STACK_OF(X509)* cert_chain_get_stack(const cert_chain_t* chain);
// Parses a primary PEM certificate and an additional concatenated PEM chain,
// building a cert_chain_t containing all certificates.
// first_pem: a null-terminated PEM block. pem_chain: a null-terminated string
// containing one or more PEM blocks concatenated.
// Returns a pointer to a cert_chain_t on success, or NULL on failure.
// Caller must free with cert_chain_free().
cert_chain_t* cert_chain_create_from_pem_chain(const char* first_pem,
                                              const char* pem_chain);
// Validates that each certificate in the chain is signed by the next certificate.
// The last certificate must be self-signed. Returns 1 on success, 0 on any verification failure.
int cert_chain_validate(const cert_chain_t* chain);
// Creates a new, empty certificate chain. Returns NULL on failure.
// Caller must free with cert_chain_free().
cert_chain_t* cert_chain_new(void);
// Adds a single PEM certificate (possibly JSON-escaped) to an existing chain.
// Returns 1 on success, 0 on failure.
int cert_chain_add_pem(cert_chain_t* chain, const char* pem);
// Parses one or more PEM certificates concatenated (possibly JSON-escaped) and adds
// them to the existing chain. Returns 1 if all were added successfully, 0 otherwise.
int cert_chain_add_pem_chain(cert_chain_t* chain, const char* pem_chain);
// Loads a public key from a PEM-formatted string (JSON-escaped allowed).
// Returns an EVP_PKEY* on success, or NULL on failure. Caller must free with pubkey_free().
// Requires <openssl/evp.h> and <openssl/pem.h> to be included by consumer.
EVP_PKEY* pubkey_from_pem(const char* pem);
// Frees a public key loaded by pubkey_from_pem(). Safe to call with NULL.
void pubkey_free(EVP_PKEY* key);
// Validates that the root certificate in the chain is signed by the provided public key.
// Returns 1 if the root cert is validly signed, 0 otherwise.
int cert_chain_validate_root(const cert_chain_t* chain, EVP_PKEY* trusted_root_pubkey);
// Placeholder for the PEM-encoded trusted root public key.
// Set this to the appropriate PEM string before calling cert_chain_validate_root().
extern const char* cert_chain_trusted_root_pubkey_pem;
// Creates a new, empty certificate chain. Returns NULL on failure.
// Caller must free with cert_chain_free().
cert_chain_t* cert_chain_new(void);
// Adds a single PEM certificate (possibly JSON-escaped) to an existing chain.
// Returns 1 on success, 0 on failure.
int cert_chain_add_pem(cert_chain_t* chain, const char* pem);
// Parses one or more PEM certificates concatenated (possibly JSON-escaped) and adds
// them to the existing chain. Returns 1 if all were added successfully, 0 otherwise.
int cert_chain_add_pem_chain(cert_chain_t* chain, const char* pem_chain);

#ifdef __cplusplus
}
#endif

#endif // CERT_CHAIN_H