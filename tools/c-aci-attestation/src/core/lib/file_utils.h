 #ifndef FILE_UTILS_H
#define FILE_UTILS_H

// Reads the contents of a file into a null-terminated string.
// path: path to the file.
// Returns a malloc'd null-terminated buffer with the file contents, or NULL on failure. Caller must free().
char* read_file(const char* path);

#endif // FILE_UTILS_H