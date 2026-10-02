/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _POSIX_C_SOURCE 200809L
#include "qpc_owner.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
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

uint64_t device_open(const char *path, const qpc_witness_v1 *witness, int tls) {
    qpc_open_options_v1 options={3,0,witness ? (tls ? 2U : 1U) : 0U,witness};
    uint64_t handle=0; qpc_error_v1 error;
    expect(qpc_owner_v1_prepare_open((const uint8_t *)path,strlen(path),&options,&handle,&error),0,&error);
    expect(qpc_owner_v1_finish_open(handle,&error),0,&error);
    return handle;
}
uint64_t device_peer_open(uint64_t parent, const char *path, uint32_t role, const uint8_t *existing) {
    uint64_t handle=0; qpc_error_v1 error;
    char *copied=strdup(path); uint8_t session[32]={0};
    if (!copied) fail("peer input allocation");
    if (existing) memcpy(session,existing,sizeof(session));
    int32_t code=existing ? qpc_peer_v1_prepare_reopen(parent,(const uint8_t *)copied,strlen(copied),1,role,session,&handle,&error) :
        qpc_peer_v1_prepare(parent,(const uint8_t *)copied,strlen(copied),1,role,&handle,&error);
    expect(code,0,&error);
    memset(copied,'x',strlen(copied)); memset(session,0,sizeof(session));
    expect(qpc_owner_v1_finish_open(handle,&error),0,&error);
    free(copied);
    return handle;
}
struct DeviceWait { uint64_t peer; int32_t code; qpc_served_v1 result; qpc_error_v1 error; atomic_int done; unsigned busy_admissions; };
static int32_t unexpected_commit(void *context, const uint8_t session[32], const uint8_t message[32],
                                 const uint8_t *plaintext, size_t length) {
    (void)context; (void)session; (void)message; (void)plaintext; (void)length;
    fail("unexpected application call in listener cancellation workload");
}
static void *device_wait(void *opaque) {
    struct DeviceWait *call=opaque;
    for (;;) {
        call->code=qpc_owner_v1_serve(call->peer,unexpected_commit,NULL,&call->result,&call->error);
        if (call->code!=QPC_BUSY || call->busy_admissions==64) break;
        /* The observing call can win first admission. Only this pre-I/O BUSY
         * is retried by the test fixture; never a transport/native failure. */
        expect(call->code,QPC_BUSY,&call->error);
        if (call->result.kind) fail("busy admission published a served event");
        call->busy_admissions++;
        struct timespec interval={0,1000000};
        if (nanosleep(&interval,NULL) && errno!=EINTR) fail("admission wait failed");
    }
    atomic_store_explicit(&call->done,1,memory_order_release);
    return NULL;
}
static uint32_t selected_role(const char *text) {
    if (!strcmp(text,"1")) return 1;
    if (!strcmp(text,"2")) return 2;
    fail("peer role");
}
struct DeviceImage { unsigned char *bytes; size_t length; };
static struct DeviceImage device_image(const char *root, const char *name) {
    char path[8192]; int n=snprintf(path,sizeof(path),"%s/%s",root,name);
    if (n<=0 || (size_t)n>=sizeof(path)) fail("state image path");
    FILE *file=fopen(path,"rb");
    if (!file || fseeko(file,0,SEEK_END)) fail("state image open");
    off_t size=ftello(file);
    if (size<=0 || size>16*1024*1024 || fseeko(file,0,SEEK_SET)) fail("state image bound");
    struct DeviceImage image={.bytes=malloc((size_t)size),.length=(size_t)size};
    if (!image.bytes || fread(image.bytes,1,image.length,file)!=image.length ||
        fgetc(file)!=EOF || ferror(file) || fclose(file)) fail("state image read");
    return image;
}
int device_command(int argc, char **argv, const qpc_witness_v1 *witness, int tls) {
    if (!strcmp(argv[1],"device-reject-open") && argc==3) {
        qpc_open_options_v1 options={3,0,witness ? (tls ? 2U : 1U) : 0U,witness};
        uint64_t parent=0; qpc_error_v1 error;
        expect(qpc_owner_v1_prepare_open((const uint8_t *)argv[2],strlen(argv[2]),&options,&parent,&error),0,&error);
        int32_t code=qpc_owner_v1_finish_open(parent,&error);
        if (!code) fail("invalid device construction admitted");
        expect(code,code,&error);
        expect(qpc_owner_v1_finish_open(parent,&error),QPC_CLOSED,&error);
        expect(qpc_owner_v1_close(parent,&error),0,&error);
        if (printf("device-rejected:%d\n",code)<0 || fflush(stdout)) fail("device refusal output");
        return 0;
    }
    if (!strcmp(argv[1],"device-open-close") && argc==3) {
        uint64_t parent=device_open(argv[2],witness,tls); qpc_error_v1 error;
        expect(qpc_owner_v1_close(parent,&error),0,&error);
        if (puts("device-open-close-passed")==EOF || fflush(stdout)) fail("device control output");
        return 0;
    }
    if (strcmp(argv[1],"device-check") || argc!=5) fail("device lifecycle arguments");
    const char *local=argv[2], *peer=argv[3];
    uint32_t role=selected_role(argv[4]);
    uint64_t parent=device_open(local,witness,tls), first=0, second=0, pending=0;
    const char *images[3]={"installation.redb","journal.redb","archives.redb"};
    struct DeviceImage before[3];
    for (size_t i=0;i<3;i++) before[i]=device_image(local,images[i]);
    qpc_error_v1 error;
    uint8_t session[32]={1}, message[32]={0}, state=255;
    message[31]=1;
    expect(qpc_owner_v1_message_status(parent,session,message,&state,&error),QPC_OWNER_KIND,&error);
    expect(qpc_peer_v1_prepare(parent,(const uint8_t *)peer,strlen(peer),1,3-role,&pending,&error),0,&error);
    expect(qpc_owner_v1_finish_open(pending,&error),QPC_SCOPE_CONFLICT,&error);
    expect(qpc_owner_v1_finish_open(pending,&error),QPC_CLOSED,&error);
    expect(qpc_owner_v1_close(pending,&error),0,&error);
    uint8_t zero[32]={0}; pending=99;
    expect(qpc_peer_v1_prepare_reopen(parent,(const uint8_t *)peer,strlen(peer),1,role,zero,&pending,&error),QPC_ARGUMENT,&error);
    if (pending) fail("invalid peer input published a handle");
    expect(qpc_peer_v1_prepare(parent,(const uint8_t *)peer,strlen(peer),1,role,&pending,&error),0,&error);
    expect(qpc_owner_v1_cancel(pending,&error),0,&error);
    expect(qpc_owner_v1_finish_open(pending,&error),QPC_CANCELLED,&error);
    expect(qpc_owner_v1_close(pending,&error),0,&error);
    first=device_peer_open(parent,peer,role,NULL);
    second=device_peer_open(parent,peer,role,NULL);
    pending=99;
    expect(qpc_peer_v1_prepare(first,(const uint8_t *)peer,strlen(peer),1,role,&pending,&error),QPC_OWNER_KIND,&error);
    if (pending) fail("peer accepted as device parent");
    uint64_t capacity[61]={0};
    for (size_t i=0;i<61;i++) {
        expect(qpc_peer_v1_prepare(parent,(const uint8_t *)peer,strlen(peer),1,role,&capacity[i],&error),0,&error);
    }
    pending=99;
    expect(qpc_peer_v1_prepare(parent,(const uint8_t *)peer,strlen(peer),1,role,&pending,&error),QPC_RESOURCE_LIMIT,&error);
    if (pending) fail("capacity failure published a handle");
    for (size_t i=0;i<61;i++) expect(qpc_owner_v1_close(capacity[i],&error),0,&error);
    expect(qpc_owner_v1_cancel(first,&error),0,&error);
    expect(qpc_owner_v1_message_status(first,session,message,&state,&error),QPC_CANCELLED,&error);
    expect(qpc_owner_v1_close(first,&error),0,&error);
    uint64_t sibling=device_peer_open(parent,peer,role,NULL);
    uint16_t port=0;
    const char *address="127.0.0.1:0";
    expect(qpc_owner_v1_listen(second,(const uint8_t *)address,strlen(address),&port,&error),0,&error);
    if (!port) fail("listener port absent");
    struct DeviceWait call={.peer=second}; pthread_t thread;
    atomic_init(&call.done,0);
    if (pthread_create(&thread,NULL,device_wait,&call)) fail("listener thread creation");
    struct timespec start, now, interval={0,2000000};
    if (clock_gettime(CLOCK_MONOTONIC,&start)) fail("clock unavailable");
    for (;;) {
        int32_t code=qpc_owner_v1_message_status(sibling,session,message,&state,&error);
        if (code==QPC_BUSY) { expect(code,QPC_BUSY,&error); break; }
        expect(code,QPC_DURABLE_ABSENT,&error);
        if (atomic_load_explicit(&call.done,memory_order_acquire)) {
            fprintf(stderr,"listener returned before parent contention: status=%d\n",call.code);
            fail("listener call did not retain parent");
        }
        if (clock_gettime(CLOCK_MONOTONIC,&now) || now.tv_sec-start.tv_sec>=3) fail("parent borrow was not observed");
        if (nanosleep(&interval,NULL) && errno!=EINTR) fail("parent wait failed");
    }
    /* BUSY above proves an unrelated child holds the actual parent service. */
    expect(qpc_owner_v1_close(parent,&error),QPC_BUSY,&error);
    expect(qpc_owner_v1_close(sibling,&error),0,&error);
    expect(qpc_peer_v1_prepare(parent,(const uint8_t *)peer,strlen(peer),1,role,&pending,&error),0,&error);
    expect(qpc_owner_v1_close(pending,&error),0,&error);
    if (clock_gettime(CLOCK_MONOTONIC,&start)) fail("clock unavailable");
    expect(qpc_owner_v1_cancel(parent,&error),0,&error);
    if (pthread_join(thread,NULL)) fail("listener thread join");
    if (clock_gettime(CLOCK_MONOTONIC,&now)) fail("clock unavailable");
    int64_t ns=(int64_t)(now.tv_sec-start.tv_sec)*1000000000LL+now.tv_nsec-start.tv_nsec;
    if (ns<0 || ns>=1000000000LL) fail("parent cancellation exceeded observation bound");
    expect(call.code,QPC_CANCELLED,&call.error);
    /* Compare while the original databases remain open: redb may maintain its
     * physical allocator/transaction metadata across close/open independently
     * of protocol admission. No such reopen occurs inside this comparison. */
    for (size_t i=0;i<3;i++) {
        struct DeviceImage after=device_image(local,images[i]);
        if (before[i].length!=after.length || memcmp(before[i].bytes,after.bytes,after.length))
            fail("peer admission changed bytes under the original live parent");
        free(before[i].bytes); free(after.bytes);
    }
    expect(qpc_owner_v1_close(parent,&error),0,&error);
    expect(qpc_owner_v1_message_status(second,session,message,&state,&error),QPC_CLOSED,&error);
    /* Idle old children do not retain private storage after successful close. */
    uint64_t reopened=device_open(local,witness,tls);
    expect(qpc_owner_v1_close(second,&error),0,&error);
    uint64_t replacement=device_peer_open(reopened,peer,role,NULL);
    char exact[64]; int n=snprintf(exact,sizeof(exact),"127.0.0.1:%u",(unsigned)port);
    if (n<=0 || (size_t)n>=sizeof(exact)) fail("listener address formatting");
    uint16_t rebound=0;
    expect(qpc_owner_v1_listen(replacement,(const uint8_t *)exact,(size_t)n,&rebound,&error),0,&error);
    if (rebound!=port) fail("peer listener not released");
    expect(qpc_owner_v1_close(replacement,&error),0,&error);
    expect(qpc_owner_v1_close(reopened,&error),0,&error);
    pending=99;
    expect(qpc_peer_v1_prepare(parent,(const uint8_t *)peer,strlen(peer),1,role,&pending,&error),QPC_CLOSED,&error);
    if (pending) fail("closed parent published a handle");
    if (printf("device-parent-lifecycle-passed:busy=%u\n",call.busy_admissions)<0 || fflush(stdout)) fail("device result output");
    return 0;
}
