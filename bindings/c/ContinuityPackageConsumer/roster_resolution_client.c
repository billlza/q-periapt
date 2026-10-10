/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "qpc_owner.h"
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(qpc_roster_refresh_resolution_v1) == 168, "resolution size");
_Static_assert(_Alignof(qpc_roster_refresh_resolution_v1) == 8, "resolution alignment");
_Static_assert(offsetof(qpc_roster_refresh_resolution_v1, journal) == 8, "journal offset");
_Static_assert(offsetof(qpc_roster_refresh_resolution_v1, previous) == 40, "previous offset");
_Static_assert(offsetof(qpc_roster_refresh_resolution_v1, target) == 80, "target offset");
_Static_assert(offsetof(qpc_roster_refresh_resolution_v1, observed) == 120, "observed offset");
_Static_assert(offsetof(qpc_roster_refresh_resolution_v1, observed_at) == 160, "time offset");

static void require(int ok, const char *what) {
    if (!ok) { fprintf(stderr, "%s\n", what); exit(1); }
}
static void read_exact(const char *root, const char *name, uint8_t *out, size_t length) {
    char path[8192];
    int n = snprintf(path, sizeof(path), "%s/%s", root, name);
    require(n > 0 && (size_t)n < sizeof(path), "fixture path");
    FILE *file = fopen(path, "rb");
    require(file != NULL, "fixture open");
    require(fread(out, 1, length, file) == length && fgetc(file) == EOF, "fixture length");
    require(fclose(file) == 0, "fixture close");
}
static uint64_t number(const uint8_t bytes[8]) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | bytes[i];
    return value;
}
static qpc_roster_checkpoint_v1 checkpoint(const char *path, const char *name) {
    uint8_t bytes[40]; read_exact(path, name, bytes, sizeof(bytes));
    qpc_roster_checkpoint_v1 result = {0};
    result.version = number(bytes); memcpy(result.digest, bytes + 8, 32);
    return result;
}
static void hex(const uint8_t bytes[32]) {
    for (size_t i = 0; i < 32; ++i) printf("%02x", bytes[i]);
    putchar('\n');
}
int main(int argc, char **argv) {
    require(argc == 3, "usage: roster_resolution_client PATH MODE");
    const char *path = argv[1], *mode = argv[2];
    uint8_t root[1985], generation[8], validity[16];
    qpc_enrollment_intent_v1 intent = {0};
    read_exact(path, "trusted-root", root, sizeof(root));
    read_exact(path, "trusted-device", intent.device, sizeof(intent.device));
    read_exact(path, "family", intent.family, sizeof(intent.family));
    read_exact(path, "trusted-generation", generation, sizeof(generation));
    read_exact(path, "trusted-validity", validity, sizeof(validity));
    intent.root = root; intent.root_length = sizeof(root); intent.generation = number(generation);
    intent.valid_from = number(validity); intent.valid_until = number(validity + 8);
    qpc_roster_checkpoint_v1 previous = checkpoint(path, "roster-previous");
    qpc_roster_checkpoint_v1 target = checkpoint(path, "roster-target");
    qpc_open_options_v1 options = {.kind = 3, .quality = 0, .carrier = 0, .witness = NULL};
    qpc_error_v1 error = {0}; uint64_t handle = 0;
    require(qpc_enrollment_v1_prepare_resume((const uint8_t *)path, strlen(path), &intent, &options, &handle, &error) == 0, "prepare original resume");
    require(qpc_owner_v1_finish_open(handle, &error) == 0, "open original enrollment");
    qpc_enrollment_status_v1 original_status = {0};
    require(qpc_enrollment_v1_status(handle, &original_status, &error) == 0, "original status");
    qpc_roster_refresh_resolution_v1 output; memset(&output, 0xa5, sizeof(output));
    uint8_t untouched[sizeof(output)]; memcpy(untouched, &output, sizeof(output));
    if (strcmp(mode, "arguments") == 0) {
        require(qpc_enrollment_v1_resolve_roster_refresh(handle, NULL, &target, &output, &error) == 1, "null input must be argument failure");
        require(memcmp(untouched, &output, sizeof(output)) == 0, "argument failure published output");
        qpc_enrollment_status_v1 status = {0};
        require(qpc_enrollment_v1_status(handle, &status, &error) == 0 && status.phase == 6, "pre-admission argument failure consumed owner");
        puts("rejected:1");
    } else {
        int expected = 0;
        if (strcmp(mode, "wrong-target") == 0) { target.version += 1; expected = 211; }
        else if (strcmp(mode, "live") == 0) { expected = 215; }
        else if (strcmp(mode, "cancel") == 0) {
            require(qpc_owner_v1_cancel(handle, &error) == 0, "cancel enrollment"); expected = 302;
        } else require(strcmp(mode, "resolve") == 0, "unknown mode");
        int code = qpc_enrollment_v1_resolve_roster_refresh(handle, &previous, &target, &output, &error);
        require(code == expected && error.code == expected, "resolution result code");
        if (expected != 0) {
            require(memcmp(untouched, &output, sizeof(output)) == 0, "failed resolution published success output");
            if (expected != 302) {
                qpc_enrollment_status_v1 status = {0};
                require(qpc_enrollment_v1_status(handle, &status, &error) == 2, "admitted failure retained usable owner");
            }
            printf("rejected:%d\n", expected);
        } else {
            require(output.reserved == 0, "reserved field");
            qpc_enrollment_status_v1 status = {0};
            require(qpc_enrollment_v1_status(handle, &status, &error) == 0, "same enrollment remains queryable");
            require(memcmp(status.signing_id, original_status.signing_id, 32) == 0, "original signing identity changed");
            require(memcmp(status.journal, output.journal, 32) == 0, "original journal identity changed");
            if (status.phase == 7) {
                require(status.previous.version == output.previous.version &&
                        memcmp(status.previous.digest, output.previous.digest, 32) == 0 &&
                        status.next.version == output.target.version &&
                        memcmp(status.next.digest, output.target.digest, 32) == 0,
                        "resolved status lost original checkpoint pair");
            } else {
                qpc_roster_checkpoint_v1 zero = {0};
                require(status.phase == 5 && memcmp(&status.previous, &zero, sizeof(zero)) == 0 &&
                        memcmp(&status.next, &zero, sizeof(zero)) == 0, "active status has residual checkpoint pair");
            }
            printf("%" PRIu32 "\n", output.outcome); hex(output.journal);
            printf("%" PRIu64 "\n", output.previous.version); hex(output.previous.digest);
            printf("%" PRIu64 "\n", output.target.version); hex(output.target.digest);
            printf("%" PRIu64 "\n", output.observed.version); hex(output.observed.digest);
            printf("%" PRIu64 "\n%" PRIu32 "\n", output.observed_at, status.phase);
        }
    }
    require(qpc_owner_v1_close(handle, &error) == 0, "close original handle");
    return 0;
}
