/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Included by the qualification client; uses the same diagnostic and ID helpers. */
_Static_assert(sizeof(qpc_setup_status_v1) == 36, "setup status ABI size");
_Static_assert(sizeof(qpc_setup_preparation_v1) == 164, "setup preparation ABI size");
_Static_assert(offsetof(qpc_setup_preparation_v1, subject) == 36, "setup subject ABI offset");

struct SetupActivation { uint64_t handle; int32_t code; qpc_error_v1 error; };
static void *setup_activation(void *opaque) {
    struct SetupActivation *call = opaque;
    call->code = qpc_setup_v1_activate(call->handle,&call->error);
    return NULL;
}

/* Qualification-only phase receipts in the harness-owned probe log. */
static void setup_io_phase(unsigned phase) {
    const char *action=getenv("QPC_TEST_SYNC_ACTION"), *path=getenv("QPC_TEST_SYNC_LOG");
    if (!action || strcmp(action,"io") || !path || path[0]!='/' || phase<1 || phase>4)
        fail("setup I/O phase requires its owned probe");
    int fd=open(path,O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW);
    struct stat st;
    if (fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() ||
        (st.st_mode&0777)!=0600 || st.st_nlink!=1) fail("setup I/O phase receipt shape");
    char line[32]; int length=snprintf(line,sizeof(line),"phase %u 0\n",phase);
    if (length<=0 || (size_t)length>=sizeof(line)) fail("setup I/O phase encoding");
    size_t used=0;
    while (used<(size_t)length) {
        ssize_t count=write(fd,line+used,(size_t)length-used);
        if (count<0 && errno==EINTR) continue;
        if (count<=0) fail("setup I/O phase write");
        used+=(size_t)count;
    }
    if (close(fd)) fail("setup I/O phase close");
}
static int setup_io_activate(int argc, char **argv, const qpc_witness_v1 *witness) {
    if (argc!=3 || witness) fail("setup I/O observation requires local original state");
    qpc_open_options_v1 options={3,0,0,NULL};qpc_error_v1 error;uint64_t handle=0;
    require(qpc_setup_v1_prepare_resume((const uint8_t *)argv[2],strlen(argv[2]),&options,&handle,&error),&error);
    if (!handle) fail("setup I/O omitted handle");
    setup_io_phase(1);
    int32_t code=qpc_owner_v1_finish_open(handle,&error);record(code,&error);
    if (code && code!=QPC_DATABASE) fail("setup I/O opening error differs");
    uint8_t batch[32];
    if (!code) {
        setup_io_phase(2);
        code=qpc_setup_v1_activate(handle,&error);record(code,&error);
        if (code && code!=QPC_COMMIT_UNCERTAIN) fail("setup I/O activation error differs");
    }
    qpc_setup_status_v1 status;
    int32_t remaining=qpc_setup_v1_status(handle,&status,&error);record(remaining,&error);
    if (remaining!=(code ? QPC_CLOSED : QPC_OWNER_KIND)) fail("setup I/O retained wrong owner");
    if (!code) require(qpc_device_v1_next_account(handle,batch,&error),&error);
    setup_io_phase(3);
    require(qpc_owner_v1_close(handle,&error),&error);
    remaining=qpc_setup_v1_status(handle,&status,&error);record(remaining,&error);
    if (remaining!=QPC_CLOSED) fail("setup I/O disposal retained authority");
    setup_io_phase(4);
    printf("setup-io:%d\n",code);
    if (!code) encode(batch);
    if (fflush(stdout)) fail("setup I/O output failed");
    return 0;
}

static int setup_command(int argc, char **argv, const qpc_witness_v1 *witness, int tls) {
    if (argc < 3 || argc > 4) fail("setup arguments");
    if (!strcmp(argv[1],"setup-io-activate")) return setup_io_activate(argc,argv,witness);
    int create = !strcmp(argv[1],"setup-create");
    int prepare = !strcmp(argv[1],"setup-storage");
    int activate = !strcmp(argv[1],"setup-activate");
    int device = !strcmp(argv[1],"setup-device");
    int precancel = !strcmp(argv[1],"setup-pre-cancel");
    int cancel = !strcmp(argv[1],"setup-cancel");
    if (!create && !prepare && !activate && !device && !precancel && !cancel && strcmp(argv[1],"setup-status"))
        fail("setup selection");
    if (cancel && (argc != 4 || !witness)) fail("setup cancellation barrier missing");
    int32_t expected = 0;
    if (argc == 4 && !cancel) {
        char *end = NULL;
        errno = 0;
        long value = strtol(argv[3],&end,10);
        if (errno || !end || *end || value <= 0 || value > 10000) fail("setup expected error");
        expected = (int32_t)value;
    }
    qpc_open_options_v1 options = {3,0,witness ? (tls ? 2U : 1U) : 0U,witness};
    qpc_error_v1 error;
    uint64_t handle = 0;
    int32_t code = device ?
        qpc_owner_v1_prepare_open((const uint8_t *)argv[2],strlen(argv[2]),&options,&handle,&error) : (create || precancel) ?
        qpc_setup_v1_prepare_create((const uint8_t *)argv[2],strlen(argv[2]),&options,&handle,&error) :
        qpc_setup_v1_prepare_resume((const uint8_t *)argv[2],strlen(argv[2]),&options,&handle,&error);
    require(code,&error);
    if (!handle) fail("setup omitted handle");
    if (precancel) require(qpc_owner_v1_cancel(handle,&error),&error);
    code = qpc_owner_v1_finish_open(handle,&error);
    record(code,&error);
    if (!code && device && !expected) {
        uint8_t batch[32];
        require(qpc_device_v1_next_account(handle,batch,&error),&error);
        puts("setup-device");
        encode(batch);
    } else if (!code && (prepare || activate || cancel)) {
        if (cancel) {
            struct SetupActivation call = {.handle=handle};
            pthread_t worker;
            if (pthread_create(&worker,NULL,setup_activation,&call)) fail("setup thread create");
            wait_marker(argv[3]);
            int32_t busy = qpc_owner_v1_close(handle,&error);
            record(busy,&error);
            if (busy != QPC_BUSY) fail("active setup owner closed before join");
            qpc_setup_status_v1 status;
            busy = qpc_setup_v1_status(handle,&status,&error);
            record(busy,&error);
            if (busy != QPC_BUSY) fail("active setup owner admitted another call");
            struct timespec before, after;
            if (clock_gettime(CLOCK_MONOTONIC,&before)) fail("setup cancellation clock");
            require(qpc_owner_v1_cancel(handle,&error),&error);
            if (pthread_join(worker,NULL)) fail("setup thread join");
            if (clock_gettime(CLOCK_MONOTONIC,&after)) fail("setup cancellation clock");
            int64_t ns = (int64_t)(after.tv_sec-before.tv_sec)*1000000000LL + after.tv_nsec-before.tv_nsec;
            if (ns < 0 || ns >= 1000000000LL) fail("setup cancellation exceeded observation bound");
            record(call.code,&call.error);
            if (call.code != QPC_ANCHOR) fail("setup witness cancellation error differed");
            int32_t consumed = qpc_setup_v1_status(handle,&status,&error);
            record(consumed,&error);
            if (consumed != QPC_CLOSED) fail("failed setup activation retained authority");
            printf("setup-cancelled:218:%lld\n",(long long)(ns/1000000LL));
        } else if (prepare) {
            qpc_setup_preparation_v1 result;
            code = qpc_setup_v1_prepare_storage(handle,&result,&error);
            record(code,&error);
            if (!code && !expected) {
                printf("setup-prepared:%u\n",result.protection);
                encode(result.journal);
                for (size_t i=0;i<sizeof(result.subject);++i) printf("%02x",result.subject[i]);
                if (putchar('\n') == EOF) fail("setup subject output");
                encode(result.image_digest);
            }
        } else {
            code = qpc_setup_v1_activate(handle,&error);
            record(code,&error);
            if (!code && !expected) {
                uint8_t batch[32];
                require(qpc_device_v1_next_account(handle,batch,&error),&error);
                qpc_setup_status_v1 status;
                int32_t kind = qpc_setup_v1_status(handle,&status,&error);
                record(kind,&error);
                if (kind != QPC_OWNER_KIND) fail("activated handle retained setup authority");
                puts("setup-activated");
                encode(batch);
            }
        }
    } else if (!code && !expected) {
        qpc_setup_status_v1 status;
        require(qpc_setup_v1_status(handle,&status,&error),&error);
        uint8_t id[32];
        int32_t kind = qpc_device_v1_next_account(handle,id,&error);
        record(kind,&error);
        if (kind != QPC_OWNER_KIND) fail("setup released operational authority");
        printf("setup-status:%u\n",status.phase);
        encode(status.journal);
    }
    if (code != expected) {
        fprintf(stderr,"setup status=%d expected=%d\n",code,expected);
        fail("setup outcome differs");
    }
    require(qpc_owner_v1_close(handle,&error),&error);
    if (expected) printf("setup-refused:%d\n",expected);
    if (fflush(stdout)) fail("setup output failed");
    return 0;
}
