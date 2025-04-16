/*
 * Portions Copyright (c) Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "security_context.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Reads a file from the UVM_SECURITY_CONTEXT_DIR and returns its contents as a malloc'd buffer (caller must free)
// Returns 0 on success, nonzero on error
int get_security_context_file(const char* file_path, char** out_buf, size_t* out_len) {
    if (!out_buf) return -1;
    *out_buf = NULL;
    if (out_len) *out_len = 0;
    const char* dir = getenv("UVM_SECURITY_CONTEXT_DIR");
    if (!dir) return -1;
    size_t full_path_len = strlen(dir) + strlen(file_path) + 1;
    char* full_path = (char*)malloc(full_path_len);
    if (!full_path) return -1;
    strcpy(full_path, dir);
    strcat(full_path, file_path);
    FILE* f = fopen(full_path, "rb");
    free(full_path);
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return -1; }
    char* buf = (char*)malloc(sz+1);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, sz, f);
    fclose(f);
    buf[n] = 0;
    *out_buf = buf;
    if (out_len) *out_len = n;
    return 0;
}
