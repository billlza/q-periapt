/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_CLIENT_INPUTS_H
#define QPC_CLIENT_INPUTS_H
/* Bounded public qualification inputs; never loads a private owner or infers trust. */
#include <stdint.h>
#include <stdio.h>
#include "consumer_input.h"
static int load(const char *directory, const char *name, uint8_t *out,
                size_t maximum, size_t *length) {
    char path[4096];
    int n = snprintf(path, sizeof path, "%s/%s", directory, name);
    if (n < 0 || (size_t)n >= sizeof path) return 1;
    FILE *file = qpc_input_file(path);
    if (!file) return 1;
    *length = fread(out, 1, maximum, file);
    int extra = fgetc(file), failed = ferror(file) || !*length || extra != EOF;
    return fclose(file) || failed;
}
static int fixed(const char *directory, const char *name, uint8_t *out, size_t length) {
    size_t actual = 0;
    return load(directory, name, out, length, &actual) || actual != length;
}
static int number(const char *directory, const char *name, uint64_t *out) {
    uint8_t bytes[8];
    if (fixed(directory, name, bytes, sizeof bytes)) return 1;
    *out = 0;
    for (size_t i = 0; i < sizeof bytes; i++) *out = (*out << 8) | bytes[i];
    return 0;
}
#endif
