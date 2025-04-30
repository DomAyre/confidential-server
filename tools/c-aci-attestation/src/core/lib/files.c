 #include "files.h"
 #include <stdio.h>
 #include <stdlib.h>

// Reads the entire contents of the file at 'path' into a malloc'd buffer.
// Returns a null-terminated string, or NULL on failure. Caller must free().
char* read_file(const char* path) {
    FILE* f = fopen(path, "rb");

    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }

    long size = ftell(f);
    if (size < 0) { fclose(f); return NULL; }

    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

    char* buffer = malloc(size + 1);
    if (!buffer) { fclose(f); return NULL; }

    size_t read_size = fread(buffer, 1, size, f);
    fclose(f);
    if (read_size != (size_t)size) { free(buffer); return NULL; }

    buffer[size] = '\0';
    return buffer;
}