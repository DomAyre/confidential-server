#include "host_amd_certs.h"
#include "file_utils.h"
#include "base64.h"
#include "embedded_examples.h"
#include <glob.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Decode a Base64 buffer (length b64_len) into a null-terminated JSON string.
// desc is used in error messages to identify the source.
static char* decode_cert_blob(const char* b64, size_t b64_len, const char* desc) {
    size_t raw_len = 0;
    uint8_t* raw = base64_decode(b64, b64_len, &raw_len);
    if (!raw) {
        fprintf(stderr, "Failed to decode host AMD certificates: %s\n", desc);
        return NULL;
    }
    char* json = malloc(raw_len + 1);
    if (!json) {
        free(raw);
        return NULL;
    }
    memcpy(json, raw, raw_len);
    json[raw_len] = '\0';
    free(raw);
    return json;
}

// Common helper: read a Base64 file and decode to JSON string
static char* decode_cert_file(const char* path) {
    char* b64 = read_file(path);
    if (!b64) return NULL;
    size_t b64_len = strlen(b64);
    char* json = decode_cert_blob(b64, b64_len, path);
    free(b64);
    return json;
}

// Load and decode host AMD certs from embedded virtual example
static char* get_host_amd_certs_virtual(void) {
    size_t b64_len = host_amd_certs_b64_end - host_amd_certs_b64_start;
    return decode_cert_blob(
        (const char*)host_amd_certs_b64_start,
        b64_len,
        "embedded examples/host-amd-certs-base64"
    );
}

// Attempt to load and decode host AMD certs from ACI security context
static char* get_host_amd_certs_aci(void) {
    glob_t g = {0};
    if (glob("/security_context_*/host-amd-certs-base64", 0, NULL, &g) != 0 || g.gl_pathc == 0) {
        globfree(&g);
        return NULL;
    }
    char* json = decode_cert_file(g.gl_pathv[0]);
    globfree(&g);
    return json;
}

// Public API: try ACI first, fall back to virtual
char* get_host_amd_certs(void) {
    char* certs = get_host_amd_certs_aci();
    if (certs) return certs;
    return get_host_amd_certs_virtual();
}