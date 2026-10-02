/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _POSIX_C_SOURCE 200809L
#include "qpc_owner.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static _Noreturn void fail(const char *reason) {
    fprintf(stderr, "C opening failure: %s\n", reason);
    exit(1);
}
static void expect(int32_t code, int32_t wanted, const qpc_error_v1 *error) {
    if (code != wanted || error->code != code || error->length > sizeof(error->message) ||
        error->truncated > 1 || ((code == 0) != (error->length == 0))) {
        fprintf(stderr, "opening status=%d expected=%d\n", code, wanted);
        fail("diagnostic or status differs");
    }
}
static void wait_marker(const char *path) {
    struct timespec start, now, interval = {0, 25000000};
    if (clock_gettime(CLOCK_MONOTONIC, &start)) fail("clock unavailable");
    for (;;) {
        FILE *file = fopen(path, "rb");
        if (file) {
            int byte = fgetc(file), end = fgetc(file), bad = ferror(file);
            if (fclose(file) || bad || byte != '1' || end != EOF) fail("invalid socket barrier");
            return;
        }
        if (errno != ENOENT) fail("barrier read failed");
        if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 10)
            fail("socket barrier timed out");
        if (nanosleep(&interval, NULL) && errno != EINTR) fail("wait failed");
    }
}
struct Opening { uint64_t handle; int32_t code; qpc_error_v1 error; };
static void *finish_call(void *opaque) {
    struct Opening *call = opaque;
    call->code = qpc_owner_v1_finish_open(call->handle, &call->error);
    return NULL;
}
int opening_command(int argc, char **argv, const qpc_witness_v1 *witness, int tls, const uint8_t *existing) {
    if (argc < 4) fail("opening arguments");
    int cancel = !strcmp(argv[1], "opening-cancel");
    int precancel = !strcmp(argv[1], "opening-pre-cancel");
    if (!cancel && !precancel && strcmp(argv[1], "opening-prepare")) fail("opening mode");
    uint32_t kind = !strcmp(argv[3], "operational") ? 1U : !strcmp(argv[3], "recovery") ? 2U : 0U;
    if (!kind || argc != (cancel ? 5 : 4) || (cancel && kind != 1) || (existing && kind != 1)) fail("opening selection");
    char *path = strdup(argv[2]);
    char *address = witness ? strndup((const char *)witness->address, witness->address_length) : NULL;
    if (!path || (witness && !address)) fail("input copy allocation");
    qpc_witness_v1 selected = {0};
    if (witness) selected = (qpc_witness_v1){(const uint8_t *)address, witness->address_length, witness->timeout_ms};
    qpc_open_options_v1 options = {kind, kind == 1 ? 1U : 0U, witness ? (tls ? 2U : 1U) : 0U,
                                   witness ? &selected : NULL};
    qpc_error_v1 error;
    uint64_t handle = 0;
    uint8_t selected_session[32] = {0};
    if (existing) memcpy(selected_session, existing, sizeof(selected_session));
    int32_t prepared = existing ? qpc_owner_v1_prepare_reopen((const uint8_t *)path, strlen(path),
        &options, selected_session, &handle, &error) :
        qpc_owner_v1_prepare_open((const uint8_t *)path, strlen(path), &options, &handle, &error);
    expect(prepared, 0, &error);
    memset(selected_session, 0, sizeof(selected_session));
    if (!handle) fail("zero pending handle");
    /* The actual subsequent open must use owned copies, including nested endpoint bytes. */
    memset(path, 'x', strlen(path));
    if (address) memset(address, 'x', selected.address_length);
    /* Keep mutated buffers alive through activation: a retained-pointer bug must
     * read changed valid memory, not depend on undefined use-after-free behavior. */
    options = (qpc_open_options_v1){0}; selected = (qpc_witness_v1){0};
    uint32_t count = 99;
    expect(qpc_recovery_v1_session_count(handle, &count, &error), QPC_OWNER_KIND, &error);
    if (precancel) {
        expect(qpc_owner_v1_cancel(handle, &error), 0, &error);
        expect(qpc_owner_v1_finish_open(handle, &error), QPC_CANCELLED, &error);
        expect(qpc_owner_v1_finish_open(handle, &error), QPC_CLOSED, &error);
        expect(qpc_recovery_v1_session_count(handle, &count, &error), QPC_CLOSED, &error);
        printf("prepared-pre-cancel:%u\n", kind);
    } else if (cancel) {
        struct Opening call = {.handle = handle};
        pthread_t thread;
        if (pthread_create(&thread, NULL, finish_call, &call)) fail("thread creation");
        wait_marker(argv[4]);
        expect(qpc_owner_v1_close(handle, &error), QPC_BUSY, &error);
        expect(qpc_owner_v1_finish_open(handle, &error), QPC_BUSY, &error);
        expect(qpc_recovery_v1_session_count(handle, &count, &error), QPC_BUSY, &error);
        struct timespec start, end;
        if (clock_gettime(CLOCK_MONOTONIC, &start)) fail("clock unavailable");
        expect(qpc_owner_v1_cancel(handle, &error), 0, &error);
        if (pthread_join(thread, NULL)) fail("thread join");
        if (clock_gettime(CLOCK_MONOTONIC, &end)) fail("clock unavailable");
        int64_t ns = (int64_t)(end.tv_sec-start.tv_sec)*1000000000LL + end.tv_nsec-start.tv_nsec;
        if (ns < 0 || ns >= 1000000000LL) fail("constructor cancellation exceeded observation bound");
        /* Preserve the native witness failure, not a fabricated successful open. */
        expect(call.code, 218, &call.error);
        expect(qpc_owner_v1_finish_open(handle, &error), QPC_CLOSED, &error);
        expect(qpc_recovery_v1_session_count(handle, &count, &error), QPC_CLOSED, &error);
        printf("prepared-cancelled:218:%lld\n", (long long)(ns/1000000LL));
    } else {
        expect(qpc_owner_v1_finish_open(handle, &error), 0, &error);
        expect(qpc_owner_v1_finish_open(handle, &error), QPC_OWNER_KIND, &error);
        expect(qpc_recovery_v1_session_count(handle, &count, &error), kind == 2 ? 0 : QPC_OWNER_KIND, &error);
        printf("prepared-open:%u\n", kind);
    }
    expect(qpc_owner_v1_close(handle, &error), 0, &error);
    expect(qpc_owner_v1_cancel(handle, &error), QPC_CLOSED, &error);
    free(path); free(address);
    if (fflush(stdout)) fail("output failed");
    return 0;
}
