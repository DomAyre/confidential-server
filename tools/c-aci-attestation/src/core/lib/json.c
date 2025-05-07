#include <stdlib.h>
#include <string.h>

char* get_json_field(const char* json, const char* key) {
    char* key_pos = strstr(json, key);
    if (!key_pos) return NULL;
    char* colon = strchr(key_pos, ':');
    if (!colon) return NULL;
    char* val_start = colon + 1;
    while (*val_start == ' ' || *val_start == '\"') val_start++;
    char* val_end = strchr(val_start, '\"');
    if (!val_end) return NULL;
    size_t len = val_end - val_start;
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    for (size_t i = 0; i < len; i++) {
        result[i] = val_start[i];
    }
    result[len] = '\0';
    return result;
}