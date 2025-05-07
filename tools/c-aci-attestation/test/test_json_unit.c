// test_json_unit.c - Unit tests for get_json_field

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lib/json.h"

static int test_simple(void) {
    const char *json = "{\"foo\":\"bar\"}";
    char *val = get_json_field(json, "foo");
    if (!val) {
        fprintf(stderr, "[simple] Expected non-NULL\n");
        return 1;
    }
    if (strcmp(val, "bar") != 0) {
        fprintf(stderr, "[simple] FAILED: expected 'bar', got '%s'\n", val);
        free(val);
        return 1;
    }
    free(val);
    printf("[PASS] simple extraction\n");
    return 0;
}

static int test_spaces(void) {
    const char *json = "{\"foo\" :   \"baz\"}";
    char *val = get_json_field(json, "foo");
    if (!val) {
        fprintf(stderr, "[spaces] Expected non-NULL\n");
        return 1;
    }
    if (strcmp(val, "baz") != 0) {
        fprintf(stderr, "[spaces] FAILED: expected 'baz', got '%s'\n", val);
        free(val);
        return 1;
    }
    free(val);
    printf("[PASS] spaces handling\n");
    return 0;
}

static int test_missing(void) {
    char *val = get_json_field("{}", "foo");
    if (val) {
        fprintf(stderr, "[missing] Expected NULL\n");
        free(val);
        return 1;
    }
    printf("[PASS] missing key returns NULL\n");
    return 0;
}

int main(void) {
    // Declare test suite
    printf("=== test_json_unit ===\n");
    if (test_simple()) return 1;
    if (test_spaces()) return 1;
    if (test_missing()) return 1;
    printf("All tests passed\n");
    return 0;
}