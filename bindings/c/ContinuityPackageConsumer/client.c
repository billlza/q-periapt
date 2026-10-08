/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1 /* Darwin exposes its no-follow open flags here. */
#endif
#define _POSIX_C_SOURCE 200809L
#include "qpc_owner.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(qpc_error_v1) == 524, "diagnostic ABI size");
_Static_assert(offsetof(qpc_error_v1, message) == 12, "diagnostic ABI offset");
_Static_assert(sizeof(qpc_served_v1) == 72, "served ABI size");
_Static_assert(offsetof(qpc_served_v1, duplicate) == 68, "served ABI offset");
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
static int32_t open_configured(const char *path,const qpc_witness_v1 *witness,int witness_tls,
                              const uint8_t *existing, uint64_t *handle,qpc_error_v1 *error) {
    if (existing) {
        qpc_open_options_v1 options = {.kind=1,.quality=1,.carrier=witness ? (witness_tls ? 2U : 1U) : 0U,.witness=witness};
        int32_t code = qpc_owner_v1_prepare_reopen((const uint8_t *)path,strlen(path),&options,existing,handle,error);
        if (code) return code;
        code = qpc_owner_v1_finish_open(*handle,error);
        if (code) {
            qpc_error_v1 disposal;
            if (qpc_owner_v1_close(*handle,&disposal) != 0) fail("failed restore did not release pending owner");
            *handle = 0;
        }
        return code;
    }
    if (witness && witness_tls)
        return qpc_owner_v1_open_witness_tls((const uint8_t *)path,strlen(path),1,witness,handle,error);
    return witness ? qpc_owner_v1_open_witness((const uint8_t *)path,strlen(path),1,witness,handle,error)
                   : qpc_owner_v1_open((const uint8_t *)path,strlen(path),1,handle,error);
}
static uint64_t open_owner(const char *path,const qpc_witness_v1 *witness,int witness_tls,const uint8_t *existing) {
    qpc_error_v1 error;
    uint64_t handle = 0;
    int32_t code = open_configured(path,witness,witness_tls,existing,&handle,&error);
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
    const uint8_t original[]="/nonexistent-witness-fixture";
    handle=99;
    code=qpc_owner_v1_open_witness(original,sizeof(original)-1,1,NULL,&handle,&error);
    record(code,&error);
    if (code!=QPC_ARGUMENT || handle) fail("missing witness options accepted");
    const uint8_t endpoint[]="127.0.0.1:1";
    qpc_witness_v1 witness={.address=endpoint,.address_length=sizeof(endpoint)-1,.timeout_ms=0};
    handle=99;
    code=qpc_recovery_v1_open_witness(original,sizeof(original)-1,&witness,&handle,&error);
    record(code,&error);
    if (code!=QPC_ARGUMENT || handle) fail("unbounded witness timeout accepted");
    witness.timeout_ms=10001;
    code=qpc_owner_v1_open_witness(original,sizeof(original)-1,1,&witness,&handle,&error);
    record(code,&error);
    if (code!=QPC_ARGUMENT || handle) fail("oversized witness timeout accepted");
    handle=99;
    code=qpc_owner_v1_open_witness_tls(original,sizeof(original)-1,1,NULL,&handle,&error);
    record(code,&error);
    if (code!=QPC_ARGUMENT || handle) fail("missing TLS witness options accepted");
    handle=99;
    code=qpc_recovery_v1_open_witness_tls(original,sizeof(original)-1,&witness,&handle,&error);
    record(code,&error);
    if (code!=QPC_ARGUMENT || handle) fail("oversized TLS witness timeout accepted");
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
struct Application {
    uint64_t handle;
    const char *path, *mode;
    unsigned calls, created;
};
/* This test application atomically publishes effect+dedup bytes under one ID.
 * A retry compares the complete original record; it never overwrites a conflict.
 * SDK callback success follows both file and directory fsync. */
static int existing_effect(int directory, const char *name, const uint8_t *bytes, size_t length) {
    int file = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (file < 0) return errno == ENOENT ? 1 : -1;
    struct stat info;
    uint8_t observed[64 + sizeof(payload)];
    size_t used = 0;
    int bad = fstat(file, &info) || !S_ISREG(info.st_mode) || info.st_size != (off_t)length;
    while (!bad && used < sizeof(observed)) {
        ssize_t count = read(file, observed + used, sizeof(observed) - used);
        if (count < 0) { if (errno == EINTR) continue; bad = 1; break; }
        if (!count) break;
        used += (size_t)count;
    }
    if (!bad && (used != length || memcmp(observed, bytes, length))) bad = 1;
    if (!bad && fsync(file)) bad = 1;
    if (close(file)) bad = 1;
    if (!bad && fsync(directory)) bad = 1;
    return bad ? -1 : 0;
}
static int persist_effect(struct Application *app, const uint8_t session[32],
                          const uint8_t message[32], const uint8_t *plaintext, size_t length) {
    if (length != sizeof(payload)-1 || memcmp(plaintext, payload, length)) return -1;
    uint8_t bytes[64 + sizeof(payload)-1];
    memcpy(bytes, session, 32); memcpy(bytes+32, message, 32); memcpy(bytes+64, plaintext, length);
    char name[sizeof("application-") + 64], temporary[sizeof(name) + 64];
    memcpy(name, "application-", sizeof("application-")-1);
    for (size_t i = 0; i < 32; ++i) {
        int n = snprintf(name + sizeof("application-")-1 + i*2, 3, "%02x", message[i]);
        if (n != 2) return -1;
    }
    int n = snprintf(temporary, sizeof(temporary), ".%s.%ld.tmp", name, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(temporary)) return -1;
    int directory = open(app->path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return -1;
    int found = existing_effect(directory, name, bytes, sizeof(bytes));
    if (found != 1) { if (close(directory)) return -1; return found; }
    int file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (file < 0) { if (close(directory)) return -1; return -1; }
    int bad = 0;
    size_t used = 0;
    while (used < sizeof(bytes)) {
        ssize_t count = write(file, bytes+used, sizeof(bytes)-used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { bad = 1; break; }
        used += (size_t)count;
    }
    if (!bad && fsync(file)) bad = 1;
    if (close(file)) bad = 1;
    if (!bad) {
        if (linkat(directory, temporary, directory, name, 0) == 0) app->created++;
        else if (errno != EEXIST) bad = 1;
    }
    if (unlinkat(directory, temporary, 0)) bad = 1;
    if (!bad && existing_effect(directory, name, bytes, sizeof(bytes)) != 0) bad = 1;
    if (close(directory)) bad = 1;
    return bad ? -1 : 0;
}
static int32_t commit_application(void *opaque, const uint8_t session[32],
                                  const uint8_t message[32], const uint8_t *plaintext, size_t length) {
    struct Application *app = opaque;
    app->calls++;
    qpc_error_v1 nested;
    int32_t code = qpc_owner_v1_close(app->handle, &nested);
    record(code, &nested);
    if (code != QPC_BUSY) fail("callback reentrant close did not preserve owner");
    if (!strcmp(app->mode, "fail-before")) return 17;
    if (persist_effect(app, session, message, plaintext, length)) return 31;
    if (!strcmp(app->mode, "uncertain")) return 29;
    if (!strcmp(app->mode, "crash-after")) exit(77);
    return 0;
}
static void serve(uint64_t handle, const char *path, const char *mode, const char *session_text) {
    if (strcmp(mode, "bootstrap") && strcmp(mode, "message") && strcmp(mode, "fail-before") &&
        strcmp(mode, "uncertain") && strcmp(mode, "crash-after") && strcmp(mode, "rekey") &&
        strcmp(mode, "pre-cancel") && strcmp(mode, "deadline")) fail("unknown server mode");
    struct Application app = {.handle=handle, .path=path, .mode=mode};
    qpc_error_v1 error;
    uint16_t port = 0;
    const uint8_t bind_address[] = "127.0.0.1:0";
    require(qpc_owner_v1_listen(handle, bind_address, sizeof(bind_address)-1, &port, &error), &error);
    if (!port) fail("listener returned zero port");
    if (printf("listening:%u\n", (unsigned)port) < 0 || fflush(stdout)) fail("readiness output failed");
    uint16_t second = 0;
    int32_t code = qpc_owner_v1_listen(handle, bind_address, sizeof(bind_address)-1, &second, &error);
    record(code, &error);
    if (code != QPC_STATE || second != 0) fail("listener replaced without closing its owner");
    if (!strcmp(mode, "rekey")) {
        uint8_t session[32]; uint64_t epoch = 0;
        if (!session_text) fail("rekey server session missing");
        decode(session_text, session);
        require(qpc_owner_v1_serve_rekey(handle, session, &epoch, &error), &error);
        if (epoch != 1) fail("server rekey target differs");
        puts("server-rekey-1");
        return;
    }
    qpc_served_v1 result;
    code = qpc_owner_v1_serve(handle, NULL, &app, &result, &error);
    record(code, &error);
    if (code != QPC_ARGUMENT) fail("missing callback accepted");
    if (!strcmp(mode, "pre-cancel")) require(qpc_owner_v1_cancel(handle, &error), &error);
    code = qpc_owner_v1_serve(handle, commit_application, &app, &result, &error);
    record(code, &error);
    if (!strcmp(mode, "fail-before") || !strcmp(mode, "uncertain")) {
        if (code != QPC_APPLICATION || app.calls != 1 || result.kind != 0)
            fail("callback failure was relabelled as consumption");
        char diagnostic[sizeof(error.message)+1];
        memcpy(diagnostic, error.message, error.length); diagnostic[error.length] = 0;
        if (!strstr(diagnostic, !strcmp(mode, "fail-before") ? "callback returned 17;" : "callback returned 29;"))
            fail("callback status was replaced");
        printf("application-failed:%u:%u\n", app.calls, app.created);
    } else if (!strcmp(mode, "deadline")) {
        if (code != QPC_DEADLINE || app.calls || result.kind != 0)
            fail("listener and TLS did not preserve the invocation deadline");
        puts("server-deadline");
    } else if (!strcmp(mode, "pre-cancel")) {
        if (code != QPC_CANCELLED || app.calls || result.kind != 0) fail("cancelled listener consumed input");
        puts("server-cancelled");
    } else {
        require(code, &error);
        printf("served:%u:%u:%u:%u\n", result.kind, result.duplicate, app.calls, app.created);
        encode(result.session); encode(result.message);
    }
}
int recovery_command(int argc, char **argv,const qpc_witness_v1 *witness,int witness_tls);
int opening_command(int argc, char **argv, const qpc_witness_v1 *witness, int witness_tls, const uint8_t *existing);
int device_command(int argc, char **argv, const qpc_witness_v1 *witness, int witness_tls);
uint64_t device_open(const char *path, const qpc_witness_v1 *witness, int witness_tls);
uint64_t device_peer_open(uint64_t parent, const char *path, uint32_t role, const uint8_t *existing);
#include "account_client.c"
#include "setup_client.c"
#include "enrollment_client.c"
#include "retirement_client.c"
#include "credential_peer_client.c"
#include "peer_roster_client.c"
int main(int argc, char **argv) {
    if (argc < 2) fail("missing command");
    if (!strcmp(argv[1], "retired")) return retirement_command(argc, argv);
    qpc_witness_v1 options; const qpc_witness_v1 *witness=NULL; int witness_tls=0;
    if (!strcmp(argv[1],"--witness") || !strcmp(argv[1],"--witness-tls")) {
        if (argc<5) fail("witness arguments");
        witness_tls=!strcmp(argv[1],"--witness-tls");
        options=(qpc_witness_v1){.address=(const uint8_t *)argv[2],.address_length=strlen(argv[2]),.timeout_ms=3000};
        witness=&options; argc-=2; argv+=2;
    }
    const char *device_path=NULL; uint32_t device_role=0; int enrolled_parent=0,continued_parent=0,independent_parent=0;
    if (!strcmp(argv[1], "--device-parent") || !strcmp(argv[1], "--enrollment-parent") || !strcmp(argv[1], "--continued-enrollment-parent") || !strcmp(argv[1], "--independent-policy-parent")) {
        independent_parent=!strcmp(argv[1], "--independent-policy-parent");
        continued_parent=!strcmp(argv[1], "--continued-enrollment-parent");
        enrolled_parent=continued_parent || independent_parent || !strcmp(argv[1], "--enrollment-parent");
        if (argc < 6) fail("device parent arguments");
        device_path=argv[2];
        device_role=!strcmp(argv[3],"1") ? 1U : !strcmp(argv[3],"2") ? 2U : 0U;
        if (!device_role) fail("device role");
        argc-=3; argv+=3;
    }
    uint8_t selected[32]; const uint8_t *existing=NULL;
    if (!strcmp(argv[1],"--session")) {
        if (argc < 5) fail("existing session arguments");
        decode(argv[2],selected); existing=selected; argc-=2; argv+=2;
        if (!strncmp(argv[1],"recover-",8) || !strcmp(argv[1],"self-check"))
            fail("existing session requires an operational command");
    }
    if((continued_parent || independent_parent) && strncmp(argv[1],"account-",8) && strncmp(argv[1],"peer-roster-",12) && (!existing || !strcmp(argv[1],"connect") ||
        (!strcmp(argv[1],"serve") && argc>3 && !strcmp(argv[3],"bootstrap"))))
        fail("continued enrollment requires an existing operational session");
    self_check();
    if (!strcmp(argv[1],"continued-peer-refused") || !strcmp(argv[1],"continued-peer-admit")) {
        if(device_path || existing) fail("continued peer command owns its enrollment");
        return continued_peer_command(argc,argv,witness,witness_tls);
    }
    if (!strcmp(argv[1],"credential-peer-check")) {
        if (device_path || existing || witness) fail("credential peer check owns its local-only parent");
        return credential_peer_check(argc,argv);
    }
    if (!strncmp(argv[1],"enrollment-",11)) {
        if(device_path || existing) fail("enrollment command owns its registration");
        return enrollment_command(argc,argv,witness,witness_tls);
    }
    if (!strncmp(argv[1],"setup-",6)) {
        if (device_path || existing) fail("setup command owns its explicit installation");
        return setup_command(argc,argv,witness,witness_tls);
    }
    if (!strncmp(argv[1],"peer-roster-",12)) {
        if(!device_path || existing || continued_parent || strcmp(device_path,argv[2])) fail("peer roster requires exact original device parent");
        uint64_t parent=independent_parent ? independent_policy_parent(device_path,witness,witness_tls) :
            enrolled_parent ? enrollment_parent(device_path,witness,witness_tls) : device_open(device_path,witness,witness_tls);
        return peer_roster_command(argc,argv,parent);
    }
    if (!strncmp(argv[1],"account-",8)) {
        if (existing || continued_parent) fail("account command requires its complete member sessions and supported original parent");
        if (device_path && (device_role!=1 || strcmp(device_path,argv[2]))) fail("account parent path or role differs");
        if (independent_parent && !strcmp(argv[1],"account-connect")) fail("continued account parent cannot create new bootstrap sessions");
        uint64_t parent=device_path ? (independent_parent ? independent_policy_parent(device_path,witness,witness_tls) :
            enrolled_parent ? enrollment_parent(device_path,witness,witness_tls) : device_open(device_path,witness,witness_tls)) : 0;
        return account_command(argc,argv,witness,witness_tls,parent);
    }
    if (strncmp(argv[1], "device-", 7) == 0) {
        if (device_path || existing) fail("device lifecycle mode does not accept another owner selection");
        return device_command(argc,argv,witness,witness_tls);
    }
    if (device_path && (!strncmp(argv[1],"opening-",8) || !strncmp(argv[1],"recover-",8) ||
        !strcmp(argv[1],"self-check") || !strcmp(argv[1],"reject-open"))) fail("unsupported device parent command");
    if (strncmp(argv[1], "opening-", 8) == 0) return opening_command(argc, argv, witness, witness_tls, existing);
    if (strncmp(argv[1], "recover-", 8) == 0) return recovery_command(argc, argv,witness,witness_tls);
    if (strcmp(argv[1], "self-check") == 0) {
        if (argc != 2) fail("self-check arguments");
        if (puts("self-check-passed") == EOF || fflush(stdout)) fail("output failed");
        return 0;
    }
    if (argc < 3) fail("missing original configuration");
    if (strcmp(argv[1], "reject-open") == 0) {
        qpc_error_v1 error;
        uint64_t handle = 99;
        int32_t code = open_configured(argv[2],witness,witness_tls,existing,&handle,&error);
        record(code, &error);
        if (code == 0 || handle != 0) fail("invalid original binding admitted");
        if (printf("rejected:%d\n", code) < 0 || fflush(stdout)) fail("output failed");
        return 0;
    }
    uint64_t parent = device_path ? (independent_parent ? independent_policy_parent(device_path,witness,witness_tls) : continued_parent ? continued_enrollment_parent(device_path,witness,witness_tls) :
        enrolled_parent ? enrollment_parent(device_path,witness,witness_tls) : device_open(device_path,witness,witness_tls)) : 0;
    uint64_t handle = parent ? device_peer_open(parent,argv[2],device_role,existing) :
        open_owner(argv[2],witness,witness_tls,existing);
    qpc_error_v1 error;
    if (strcmp(argv[1], "serve") == 0) {
        if (argc < 4 || argc != (!strcmp(argv[3], "rekey") ? 5 : 4)) fail("serve arguments");
        serve(handle, argv[2], argv[3], argc == 5 ? argv[4] : NULL);
    } else if (strcmp(argv[1], "connect") == 0) {
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
        int witness_failed = strcmp(argv[1], "witness-failed-send") == 0;
        int witness_cancel = strcmp(argv[1], "cancel-witness-send") == 0;
        int cancelled = strcmp(argv[1], "cancel-send") == 0;
        int busy = strcmp(argv[1], "busy-cancel") == 0;
        if ((!uncertain && !cancelled && !busy && !witness_failed && !witness_cancel && strcmp(argv[1], "send") != 0) ||
            argc != (busy || witness_cancel ? 7 : 6)) fail("send arguments");
        struct Send s = {.handle = handle, .peer = argv[3]};
        int64_t cancellation_ms = -1;
        decode(argv[4], s.session); decode(argv[5], s.message);
        if (cancelled) require(qpc_owner_v1_cancel(handle, &error), &error);
        if (busy || witness_cancel) {
            pthread_t worker;
            if (pthread_create(&worker, NULL, send_call, &s)) fail("worker creation failed");
            /* Parent observed TLS bytes, or the witness committed and sent a partial reply. */
            wait_marker(argv[6]);
            int32_t code = qpc_owner_v1_close(handle, &error);
            record(code, &error);
            if (code != QPC_BUSY) fail("close did not preserve active owner");
            struct timespec before, after;
            if (clock_gettime(CLOCK_MONOTONIC, &before)) fail("clock unavailable");
            require(qpc_owner_v1_cancel(handle, &error), &error);
            if (pthread_join(worker, NULL)) fail("worker join failed");
            if (clock_gettime(CLOCK_MONOTONIC, &after)) fail("clock unavailable");
            cancellation_ms = ((int64_t)after.tv_sec - (int64_t)before.tv_sec) * 1000
                + ((int64_t)after.tv_nsec - (int64_t)before.tv_nsec) / 1000000;
        } else {
            send_call(&s);
        }
        record(s.code, &s.error);
        if (witness_cancel) {
            if (!witness || s.code != QPC_ANCHOR || s.consumption || s.exchanges)
                fail("cancelled witness commit lost its unknown outcome");
            close_owner(handle);
            if (printf("witness-cancelled-outcome-unavailable:%lld\n", (long long)cancellation_ms) < 0
                || fflush(stdout)) fail("output failed");
            if (cancellation_ms < 0 || cancellation_ms >= 1000)
                fail("held witness socket did not observe cancellation promptly");
            return 0;
        }
        if (witness_failed) {
            if (!witness || s.code!=QPC_ANCHOR || s.consumption || s.exchanges)
                fail("witness loss was relabelled or dispatched");
            close_owner(handle);
            puts("witness-outcome-unavailable");
            return 0;
        }
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
            uint64_t reopened = parent ? device_peer_open(parent,argv[2],device_role,s.session) :
                open_owner(argv[2],witness,witness_tls,existing);
            if (reopened == handle || status(reopened, s.session, s.message) != QPC_MESSAGE_COMMITTED)
                fail("reopen changed identity or durable result");
            handle = reopened;
        }
        puts(cancelled ? "cancelled-absent" :
             (busy ? "cancelled-committed-reopened" : (uncertain ? "delivery-unknown-committed" : "consumed")));
    }
    close_owner(handle);
    if (parent) close_owner(parent);
    if (ferror(stdout) || fflush(stdout)) fail("output flush failed");
    return 0;
}
