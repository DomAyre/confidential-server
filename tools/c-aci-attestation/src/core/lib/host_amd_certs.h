#include <stdio.h>

#ifndef AMD_HOST_CERTS_H
#define AMD_HOST_CERTS_H


// Reads the base64-encoded host AMD certificates from the examples directory,
// decodes them, and returns the underlying JSON string.
// Returns a malloc'd null-terminated JSON buffer on success, or NULL on failure. Caller must free().
char* get_host_amd_certs(void);


#endif // AMD_HOST_CERTS_H