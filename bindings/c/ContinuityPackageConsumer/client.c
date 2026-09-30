/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _POSIX_C_SOURCE 200809L
#include "qpc_owner.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

_Static_assert(sizeof(qpc_error_v1) == 524, "diagnostic ABI size");
_Static_assert(offsetof(qpc_error_v1, message) == 12, "diagnostic ABI offset");
static const uint8_t payload[] = "persisted before process exit";
static const uint8_t ad[] = "owned-service";

static _Noreturn void fail(const char *message) {
    fprintf(stderr, "C consumer failure: %s\n", message);
    exit(1);
}
static void record(int32_t code, const qpc_error_v1 *error) {
    if (error->code != code || error->length > sizeof(error->message) || error->truncated > 1)
        fail("malformed diagnostic output");
    if ((code == 0 && (error->length != 0 || error->truncated != 0)) ||
        (code != 0 && error->length == 0)) fail("success/error diagnostic disagrees");
}
static void require(int32_t code, const qpc_error_v1 *error) {
    record(code, error);
    if (code) {
        fprintf(stderr, "C owner status %d: %.*s\n", code, (int)error->length,
                (const char *)error->message);
        exit(1);
    }
}
static unsigned digit(char c) {
    if (c >= '0' && c <= '9') return (unsigned)(c - '0');
    if (c >= 'a' && c <= 'f') return (unsigned)(c - 'a') + 10U;
    fail("noncanonical ID hex");
}
static void decode(const char *text, uint8_t out[32]) {
    if (strlen(text) != 64) fail("ID length differs");
    for (size_t i = 0; i < 32; ++i) out[i] = (uint8_t)((digit(text[2*i]) << 4) | digit(text[2*i+1]));
}
static void encode(const uint8_t bytes[32]) {
    for (size_t i = 0; i < 32; ++i) printf("%02x", bytes[i]);
    if (putchar('\n') == EOF || fflush(stdout) != 0) fail("output failed");
}
static uint64_t open_owner(const char *path) {
    qpc_error_v1 error;
    uint64_t handle = 0;
    int32_t code = qpc_owner_v1_open((const uint8_t *)path, strlen(path), 1, &handle, &error);
    require(code, &error);
    if (handle == 0) fail("success returned zero handle");
    return handle;
}
static void close_owner(uint64_t handle) {
    qpc_error_v1 error;
    require(qpc_owner_v1_close(handle, &error), &error);
    int32_t code = qpc_owner_v1_cancel(handle, &error);
    record(code, &error);
    if (code != QPC_CLOSED) fail("closed handle remained usable");
}
static uint8_t status(uint64_t handle, const uint8_t session[32], const uint8_t message[32]) {
    qpc_error_v1 error;
    uint8_t value = 255;
    require(qpc_owner_v1_message_status(handle, session, message, &value, &error), &error);
    return value;
}
struct Send {
    uint64_t handle;
    const char *peer;
    uint8_t session[32], message[32], consumption;
    uint16_t exchanges;
    int32_t code;
    qpc_error_v1 error;
};
static void *send_call(void *opaque) {
    struct Send *s = opaque;
    s->consumption = 0;
    s->exchanges = 0;
    s->code = qpc_owner_v1_send(s->handle, (const uint8_t *)s->peer, strlen(s->peer),
        s->session, s->message, payload, sizeof(payload)-1, ad, sizeof(ad)-1,
        &s->consumption, &s->exchanges, &s->error);
    return NULL;
}
static void wait_marker(const char *path) {
    struct timespec start, current, interval = {0, 25000000};
    if (clock_gettime(CLOCK_MONOTONIC, &start)) fail("clock unavailable");
    for (;;) {
        FILE *file = fopen(path, "rb");
        if (file) {
            int byte = fgetc(file), end = fgetc(file), bad = ferror(file);
            if (fclose(file) != 0 || bad || byte != '1' || end != EOF) fail("invalid test marker");
            return;
        }
        if (errno != ENOENT) fail("test marker read failed");
        if (clock_gettime(CLOCK_MONOTONIC, &current)) fail("clock unavailable");
        if (current.tv_sec - start.tv_sec >= 10) fail("socket barrier timed out");
        if (nanosleep(&interval, NULL) && errno != EINTR) fail("test wait failed");
    }
}
static void self_check(void) {
    qpc_error_v1 error;
    uint64_t handle = 99;
    int32_t code = qpc_owner_v1_open(NULL, 0, 1, &handle, &error);
    record(code, &error);
    if (code != QPC_ARGUMENT || handle != 0) fail("invalid path admitted");
    handle = 99;
    if (qpc_owner_v1_open(NULL, 0, 1, &handle, NULL) != QPC_ARGUMENT || handle != 99)
        fail("missing diagnostic caused an effect");
    /* Each failure occurs after reserving a construction slot. More than the
     * registry cap must not leak capacity or open/create a relative installation. */
    for (unsigned i = 0; i < 128; ++i) {
        handle = 99;
        code = qpc_owner_v1_open((const uint8_t *)"relative", 8, 1, &handle, &error);
        record(code, &error);
        if (code != QPC_PRIVATE_FILE || handle != 0) fail("failed constructor leaked capacity");
    }
    code = qpc_owner_v1_close(0, &error);
    record(code, &error);
    if (code != QPC_CLOSED) fail("unknown handle accepted");
}
int main(int argc, char **argv) {
    if (argc < 2) fail("missing command");
    self_check();
    if (strcmp(argv[1], "self-check") == 0) {
        if (argc != 2) fail("self-check arguments");
        if (puts("self-check-passed") == EOF || fflush(stdout)) fail("output failed");
        return 0;
    }
    if (argc < 3) fail("missing original configuration");
    if (strcmp(argv[1], "reject-open") == 0) {
        qpc_error_v1 error;
        uint64_t handle = 99;
        int32_t code = qpc_owner_v1_open((const uint8_t *)argv[2], strlen(argv[2]), 1, &handle, &error);
        record(code, &error);
        if (code == 0 || handle != 0) fail("invalid original binding admitted");
        if (printf("rejected:%d\n", code) < 0 || fflush(stdout)) fail("output failed");
        return 0;
    }
    uint64_t handle = open_owner(argv[2]);
    qpc_error_v1 error;
    if (strcmp(argv[1], "connect") == 0) {
        if (argc != 5) fail("connect arguments");
        uint8_t request[32], session[32];
        uint16_t exchanges = 0;
        decode(argv[4], request);
        require(qpc_owner_v1_establish(handle, (const uint8_t *)argv[3], strlen(argv[3]),
                request, session, &exchanges, &error), &error);
        if (exchanges == 0 || exchanges > 8) fail("invalid exchange accounting");
        encode(session);
    } else if (strcmp(argv[1], "next") == 0) {
        if (argc != 4) fail("next arguments");
        uint8_t session[32], message[32];
        decode(argv[3], session);
        require(qpc_owner_v1_next_message(handle, session, message, &error), &error);
        encode(message);
    } else if (strcmp(argv[1], "status") == 0) {
        if (argc != 5) fail("status arguments");
        uint8_t session[32], message[32];
        decode(argv[3], session); decode(argv[4], message);
        printf("%u\n", (unsigned)status(handle, session, message));
    } else if (strcmp(argv[1], "rekey") == 0) {
        if (argc != 5) fail("rekey arguments");
        uint8_t session[32]; uint64_t epoch = 0;
        decode(argv[4], session);
        require(qpc_owner_v1_rekey(handle, (const uint8_t *)argv[3], strlen(argv[3]),
                session, 1, &epoch, &error), &error);
        if (epoch != 1) fail("wrong completed target");
        puts("rekey-1-confirmed");
    } else {
        int uncertain = strcmp(argv[1], "uncertain-send") == 0;
        int cancelled = strcmp(argv[1], "cancel-send") == 0;
        int busy = strcmp(argv[1], "busy-cancel") == 0;
        if ((!uncertain && !cancelled && !busy && strcmp(argv[1], "send") != 0) ||
            argc != (busy ? 7 : 6)) fail("send arguments");
        struct Send s = {.handle = handle, .peer = argv[3]};
        decode(argv[4], s.session); decode(argv[5], s.message);
        if (cancelled) require(qpc_owner_v1_cancel(handle, &error), &error);
        if (busy) {
            pthread_t worker;
            if (pthread_create(&worker, NULL, send_call, &s)) fail("worker creation failed");
            wait_marker(argv[6]); /* Parent has observed actual TLS bytes on the socket. */
            int32_t code = qpc_owner_v1_close(handle, &error);
            record(code, &error);
            if (code != QPC_BUSY) fail("close did not preserve active owner");
            require(qpc_owner_v1_cancel(handle, &error), &error);
            if (pthread_join(worker, NULL)) fail("worker join failed");
        } else {
            send_call(&s);
        }
        record(s.code, &s.error);
        if (cancelled || busy) {
            if (s.code != QPC_CANCELLED || s.consumption != 0 || s.exchanges != 0)
                fail("cancellation was relabelled as success");
        } else if (uncertain) {
            if ((s.code != QPC_NETWORK && s.code != QPC_RETRY_EXHAUSTED && s.code != QPC_DEADLINE && s.code != QPC_TLS) ||
                s.consumption != 0) fail("receiver loss did not retain network uncertainty");
        } else {
            require(s.code, &s.error);
            if (s.consumption != QPC_CONSUMPTION_CONFIRMED || s.exchanges == 0 || s.exchanges > 8)
                fail("peer consumption not confirmed");
        }
        uint8_t expected = cancelled ? QPC_MESSAGE_ABSENT :
            (busy || uncertain ? QPC_MESSAGE_COMMITTED : QPC_MESSAGE_ACKNOWLEDGED);
        if (status(handle, s.session, s.message) != expected) fail("exact message status differs");
        if (busy) {
            close_owner(handle);
            uint64_t reopened = open_owner(argv[2]);
            if (reopened == handle || status(reopened, s.session, s.message) != QPC_MESSAGE_COMMITTED)
                fail("reopen changed identity or durable result");
            handle = reopened;
        }
        puts(cancelled ? "cancelled-absent" :
             (busy ? "cancelled-committed-reopened" : (uncertain ? "delivery-unknown-committed" : "consumed")));
    }
    close_owner(handle);
    if (ferror(stdout) || fflush(stdout)) fail("output flush failed");
    return 0;
}
