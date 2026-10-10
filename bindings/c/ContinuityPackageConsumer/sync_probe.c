/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Test-process-only sync interruption. Never linked into the SDK library. */
#define _GNU_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static dev_t target_device;
static ino_t target_inode;
static unsigned selected;
static int after, io_error, log_fd=-1;
static _Atomic unsigned sequence;
static _Atomic int armed;
static _Noreturn void stop_probe_at(int line_number) {
    char line[80]; int n=snprintf(line,sizeof(line),"sync probe refused at line %d\n",line_number);
    if (n<=0 || (size_t)n>=sizeof(line) || write(STDERR_FILENO,line,(size_t)n)!=n) _exit(89);
    _exit(87);
}
#define stop_probe() stop_probe_at(__LINE__)
static void event(const char *name, unsigned number, int value) {
    char line[96];
    int n=snprintf(line,sizeof(line),"%s %u %d\n",name,number,value);
    if (n<=0 || (size_t)n>=sizeof(line) || log_fd<0) stop_probe();
    size_t done=0;
    while (done<(size_t)n) {
        ssize_t size=write(log_fd,line+done,(size_t)n-done);
        if (size<0 && errno==EINTR) continue;
        if (size<=0) stop_probe();
        done+=(size_t)size;
    }
}
static int matches(int fd) {
    if (!atomic_load(&armed)) return 0;
    int old=errno; struct stat st;
    if (fstat(fd,&st)) stop_probe();
    int same=st.st_dev==target_device && st.st_ino==target_inode;
    errno=old; return same;
}
static unsigned before_sync(int fd) {
    if (!matches(fd)) return 0;
    unsigned number=atomic_fetch_add(&sequence,1)+1;
    if (number>64) stop_probe();
    int old=errno; event("before",number,0); errno=old;
    if (selected==number && !after) {
        if (!io_error) _exit(86);
        event("injected-before",number,EIO); errno=EIO; return UINT_MAX;
    }
    return number;
}
static int after_sync(unsigned number,int rc,int saved_errno) {
    if (number) {
        event("after",number,rc);
        if (rc) stop_probe();
        if (selected==number && after) {
            if (!io_error) _exit(86);
            event("injected-after",number,EIO); errno=EIO; return -1;
        }
    }
    errno=saved_errno; return rc;
}
__attribute__((constructor)) static void initialize_probe(void) {
    const char *path=getenv("QPC_TEST_SYNC_TARGET");
    const char *log=getenv("QPC_TEST_SYNC_LOG");
    const char *cut=getenv("QPC_TEST_SYNC_CUT");
    const char *side=getenv("QPC_TEST_SYNC_SIDE");
    const char *action=getenv("QPC_TEST_SYNC_ACTION");
    if (action) {
        if (strcmp(action,"io")) stop_probe();
        io_error=1;
    }
    if (!path || path[0]!='/' || !log || log[0]!='/' || !cut || !*cut || !side) stop_probe();
    for (const char *p=cut;*p;++p) {
        if (*p<'0' || *p>'9' || selected>64) stop_probe();
        selected=selected*10+(unsigned)(*p-'0');
    }
    if (selected>64 || (strcmp(side,"before") && strcmp(side,"after"))) stop_probe();
    after=!strcmp(side,"after");
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    struct stat st;
    if (fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() ||
        (st.st_mode&0777)!=0600 || st.st_nlink!=1) stop_probe();
    target_device=st.st_dev; target_inode=st.st_ino;
    if (close(fd)) stop_probe();
    log_fd=open(log,O_WRONLY|O_APPEND|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (log_fd<0) stop_probe();
    event(io_error ? "armed-io" : "armed",selected,after);
    atomic_store(&armed,1);
}
__attribute__((destructor)) static void finish_probe(void) {
    atomic_store(&armed,0);
    event("done",atomic_load(&sequence),0);
    if (close(log_fd)) stop_probe();
}

#if defined(__APPLE__)
typedef int (*Fcntl)(int,int,...);
static int probe_fcntl(int fd,int command,...);
static Fcntl original_fcntl(void) {
    /* dyld preserves this interposing image's direct reference to the original.
     * RTLD_NEXT dlsym instead resolves our interposed entry on this platform. */
    Fcntl original=fcntl;
    if (original==probe_fcntl) stop_probe();
    return original;
}

static int probe_fcntl(int fd,int command,...) {
    Fcntl original=original_fcntl();
    if (command==F_FULLFSYNC || command==F_BARRIERFSYNC) {
        unsigned number=before_sync(fd);
        if (number==UINT_MAX) return -1;
        int rc=original(fd,command), saved=errno;
        return after_sync(number,rc,saved);
    }
    switch (command) {
        case F_GETFD: case F_GETFL: case F_GETOWN:
        case F_GETNOSIGPIPE: case F_GETPROTECTIONCLASS: case F_GETPROTECTIONLEVEL:
            return original(fd,command);
        default: break;
    }
    va_list ap; va_start(ap,command); int rc;
    switch (command) {
        case F_DUPFD: case F_DUPFD_CLOEXEC: case F_SETFD: case F_SETFL: case F_SETOWN:
        case F_NOCACHE: case F_RDAHEAD: case F_SETNOSIGPIPE:
            rc=original(fd,command,va_arg(ap,int)); break;
        case F_GETLK: case F_SETLK: case F_SETLKW: case F_GETLKPID:
        case F_OFD_GETLK: case F_OFD_SETLK: case F_OFD_SETLKW:
            rc=original(fd,command,va_arg(ap,struct flock *)); break;
        case F_GETPATH: case F_GETPATH_MTMINFO: case F_GETPATH_NOFIRMLINK:
            rc=original(fd,command,va_arg(ap,char *)); break;
        default:
            /* No guessed variadic argument types or silent passthrough. */
            if (log_fd>=0) event("unsupported-fcntl",(unsigned)command,0);
            va_end(ap); stop_probe();
    }
    va_end(ap); return rc;
}
/* The typed pair avoids converting function pointers to object pointers. */
__attribute__((used,section("__DATA,__interpose,interposing")))
static struct { Fcntl replacement; Fcntl original; } interposition={probe_fcntl,fcntl};
#else
typedef int (*Sync)(int);
static int sync_call(const char *name,int fd) {
    void *symbol=dlsym(RTLD_NEXT,name); Sync original;
    _Static_assert(sizeof(original)==sizeof(symbol),"supported POSIX function pointer ABI");
    if (!symbol) stop_probe();
    memcpy(&original,&symbol,sizeof(original));
    unsigned number=before_sync(fd);
    if (number==UINT_MAX) return -1;
    int rc=original(fd), saved=errno;
    return after_sync(number,rc,saved);
}
int fsync(int fd) { return sync_call("fsync",fd); }
int fdatasync(int fd) { return sync_call("fdatasync",fd); }
#endif
