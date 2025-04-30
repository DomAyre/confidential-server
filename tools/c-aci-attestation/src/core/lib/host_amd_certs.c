#include "host_amd_certs.h"
#include "files.h"
#include "base64.h"
#include "json.h"
#include "embedded_examples.h"
#include <glob.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static char* get_host_amd_certs_virtual(void) {
    size_t host_amd_certs_b64_len = host_amd_certs_b64_end - host_amd_certs_b64_start;
    char* host_amd_certs_b64 = malloc(host_amd_certs_b64_len + 1);
    if (!host_amd_certs_b64) {
        return NULL;
    }
    memcpy(host_amd_certs_b64, host_amd_certs_b64_start, host_amd_certs_b64_len);
    host_amd_certs_b64[host_amd_certs_b64_len] = '\0';
    return host_amd_certs_b64;
}

static char* get_host_amd_certs_aci(void) {
    glob_t g = {0};
    if (glob("/security-context-*/host-amd-cert-base64", 0, NULL, &g) != 0 || g.gl_pathc == 0) {
        globfree(&g);
        return NULL;
    }
    printf("Found host AMD certs in ACI security context: %s\n", g.gl_pathv[0]);
    char* json = read_file(g.gl_pathv[0]);
    globfree(&g);
    return json;
}

char* get_host_amd_certs(void) {
    char* certs = get_host_amd_certs_aci();
    if (certs) return certs;
    return get_host_amd_certs_virtual();
}