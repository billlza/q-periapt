/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "qpc_owner.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(qpc_closure_header_v1) == 200, "closure header layout");
_Static_assert(sizeof(qpc_closure_epoch_v1) == 104, "closure epoch layout");
_Static_assert(sizeof(qpc_closure_reserved_v1) == 48, "reservation layout");
_Static_assert(sizeof(qpc_closure_unconfirmed_v1) == 64, "unknown send layout");
_Static_assert(sizeof(qpc_closure_delivery_v1) == 48, "delivery layout");
_Static_assert(sizeof(qpc_closure_status_v1) == 36, "closure status layout");
static _Noreturn void bad(const char *message) {
    fprintf(stderr, "C recovery failure: %s\n", message); exit(1);
}
static void code(int32_t actual, const qpc_error_v1 *e, int32_t expected) {
    if (e->code != actual || e->length > sizeof(e->message) || e->truncated > 1 ||
        (actual == 0 && (e->length || e->truncated)) || (actual != 0 && !e->length)) bad("diagnostic shape");
    if (actual != expected) {
        fprintf(stderr, "C recovery expected %d, got %d: %.*s\n", expected, actual, (int)e->length, (const char *)e->message);
        exit(1);
    }
}
static void hex(FILE *out, const uint8_t *bytes, size_t length) {
    for (size_t i=0; i<length; ++i) if (fprintf(out, "%02x", bytes[i]) < 0) bad("hex write");
}
static unsigned digit(char c) {
    if (c>='0' && c<='9') return (unsigned)(c-'0');
    if (c>='a' && c<='f') return (unsigned)(c-'a')+10;
    bad("ID encoding");
}
static void decode(const char *text, uint8_t id[32]) {
    if (strlen(text)!=64) bad("ID size");
    for (size_t i=0;i<32;++i) id[i]=(uint8_t)((digit(text[2*i])<<4)|digit(text[2*i+1]));
}
static uint8_t *read_file(const char *path, const char *name, size_t *length) {
    int dir=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (dir<0) bad("read directory");
    int file=openat(dir,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (file<0) bad("missing retained file");
    struct stat st;
    if (fstat(file,&st) || !S_ISREG(st.st_mode) || st.st_size<=0 || st.st_size>1048576) bad("retained file shape");
    size_t capacity=(size_t)st.st_size+1, used=0;
    uint8_t *bytes=malloc(capacity);
    if (!bytes) bad("read allocation");
    while (used<capacity) {
        ssize_t n=read(file,bytes+used,capacity-used);
        if (n<0 && errno==EINTR) continue;
        if (n<0) bad("retained read");
        if (!n) break;
        used+=(size_t)n;
    }
    if (used!=(size_t)st.st_size) bad("retained file changed");
    if (fsync(file) || fsync(dir)) bad("retained sync");
    if (close(file) || close(dir)) bad("retained close");
    bytes[used]=0; *length=used; return bytes;
}
static void retain(const char *path, const char *name, const uint8_t *bytes, size_t length, int create) {
    int dir=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (dir<0) bad("retain directory");
    struct stat st;
    if (fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)==0) {
        if (close(dir)) bad("existing directory close");
        size_t size=0; uint8_t *old=read_file(path,name,&size);
        if (size!=length || memcmp(old,bytes,length)) bad("retained original report differs");
        free(old); return;
    }
    if (errno!=ENOENT || !create) bad("original retained report unavailable");
    char temporary[128]; int n=snprintf(temporary,sizeof(temporary),".%s.%ld.tmp",name,(long)getpid());
    if (n<0 || (size_t)n>=sizeof(temporary)) bad("temporary name");
    int file=openat(dir,temporary,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if (file<0) bad("temporary report creation");
    size_t used=0;
    while (used<length) {
        ssize_t count=write(file,bytes+used,length-used);
        if (count<0 && errno==EINTR) continue;
        if (count<=0) bad("report write");
        used+=(size_t)count;
    }
    if (fsync(file)) bad("report fsync");
    if (close(file)) bad("report close");
    if (linkat(dir,temporary,dir,name,0)) bad("no-overwrite report publication");
    if (unlinkat(dir,temporary,0) || fsync(dir)) bad("report directory sync");
    if (close(dir)) bad("report directory close");
}
static uint64_t open_recovery(const char *path,const qpc_witness_v1 *witness) {
    uint64_t handle=0; qpc_error_v1 e;
    int32_t result=witness ? qpc_recovery_v1_open_witness((const uint8_t *)path,strlen(path),witness,&handle,&e)
                          : qpc_recovery_v1_open((const uint8_t *)path,strlen(path),&handle,&e);
    code(result,&e,0);
    if (!handle) bad("zero recovery handle");
    uint16_t port=99; const uint8_t address[]="127.0.0.1:0";
    code(qpc_owner_v1_listen(handle,address,sizeof(address)-1,&port,&e),&e,QPC_OWNER_KIND);
    if (port) bad("recovery owner obtained listener");
    return handle;
}
static void close_recovery(uint64_t handle) {
    qpc_error_v1 e;
    code(qpc_owner_v1_close(handle,&e),&e,0);
    code(qpc_owner_v1_cancel(handle,&e),&e,QPC_CLOSED);
}
static qpc_closure_status_v1 status(uint64_t handle) {
    qpc_error_v1 e; qpc_closure_status_v1 s;
    code(qpc_recovery_v1_status(handle,&s,&e),&e,0); return s;
}
static void saved_id(const char *path, uint8_t report[32]) {
    size_t size=0; uint8_t *bytes=read_file(path,"c-loss-report",&size);
    static const char prefix[]="QPC-C-LOSS/1\nreport ";
    size_t offset=sizeof(prefix)-1;
    if (size<offset+65 || memcmp(bytes,prefix,offset) || bytes[offset+64]!='\n') bad("saved report identity");
    char text[65]; memcpy(text,bytes+offset,64); text[64]=0; decode(text,report); free(bytes);
}
static void snapshot(uint64_t handle, const char *path, int create, uint8_t report[32]) {
    qpc_error_v1 e; qpc_closure_header_v1 h;
    code(qpc_recovery_v1_begin(handle,&h,&e),&e,0);
    if (h.role!=2 || h.peer_generation!=1 || h.epoch_count>4 || h.reserved_count>4) bad("report header scope");
    memcpy(report,h.report,32);
    char *bytes=NULL; size_t length=0; FILE *out=open_memstream(&bytes,&length);
    if (!out) bad("report stream");
    fputs("QPC-C-LOSS/1\nreport ",out); hex(out,h.report,32); fputs("\nheader ",out);
    hex(out,h.session,32); fputc(' ',out); hex(out,h.context,32); fputc(' ',out);
    hex(out,h.peer_account,32); fputc(' ',out); hex(out,h.peer_device,16);
    fprintf(out," %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %u %" PRIu64 " %u %u\n",
        h.role,h.peer_generation,h.confirmed_epoch,h.sending_epoch,h.receiving_epoch,h.has_pending_epoch,
        h.pending_epoch,h.reserved_count,h.epoch_count);
    for (uint32_t i=0;i<h.reserved_count;++i) {
        qpc_closure_reserved_v1 r; code(qpc_recovery_v1_reserved(handle,i,&r,&e),&e,0);
        fprintf(out,"reserved %u ",i); hex(out,r.message,32);
        fprintf(out," %" PRIu64 " %" PRIu64 "\n",r.plaintext_bytes,r.associated_data_bytes);
    }
    qpc_closure_reserved_v1 missing;
    code(qpc_recovery_v1_reserved(handle,h.reserved_count,&missing,&e),&e,QPC_ARGUMENT);
    for (uint32_t i=0;i<h.epoch_count;++i) {
        qpc_closure_epoch_v1 p; code(qpc_recovery_v1_epoch(handle,i,&p,&e),&e,0);
        if (p.reserved_zero || p.has_peer_sent>1 || p.resolution>2 || p.unconfirmed_count>64 || p.delivery_count>128 || p.skipped_count>128) bad("epoch shape");
        fprintf(out,"epoch %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %u %" PRIu64 " %u ",
            i,p.epoch,p.acknowledged_before,p.sent,p.consumed_before,p.received,p.has_peer_sent,p.peer_sent,p.resolution);
        hex(out,p.resolution_report,32);
        fprintf(out," %u %u %u\n",p.unconfirmed_count,p.delivery_count,p.skipped_count);
        for (uint32_t j=0;j<p.unconfirmed_count;++j) {
            qpc_closure_unconfirmed_v1 u; code(qpc_recovery_v1_unconfirmed(handle,i,j,&u,&e),&e,0);
            fprintf(out,"unconfirmed %u %u ",i,j); hex(out,u.message,32); fputc(' ',out); hex(out,u.ciphertext_digest,32); fputc('\n',out);
        }
        for (uint32_t j=0;j<p.delivery_count;++j) {
            qpc_closure_delivery_v1 d; code(qpc_recovery_v1_delivery(handle,i,j,&d,&e),&e,0);
            fprintf(out,"delivery %u %u ",i,j); hex(out,d.message,32);
            fprintf(out," %" PRIu64 " %" PRIu64 "\n",d.index,d.plaintext_bytes);
        }
        for (uint32_t j=0;j<p.skipped_count;++j) {
            uint64_t position=0; code(qpc_recovery_v1_skipped(handle,i,j,&position,&e),&e,0);
            fprintf(out,"skipped %u %u %" PRIu64 "\n",i,j,position);
        }
        qpc_closure_unconfirmed_v1 u; qpc_closure_delivery_v1 d; uint64_t skipped;
        code(qpc_recovery_v1_unconfirmed(handle,i,p.unconfirmed_count,&u,&e),&e,QPC_ARGUMENT);
        code(qpc_recovery_v1_delivery(handle,i,p.delivery_count,&d,&e),&e,QPC_ARGUMENT);
        code(qpc_recovery_v1_skipped(handle,i,p.skipped_count,&skipped,&e),&e,QPC_ARGUMENT);
    }
    qpc_closure_epoch_v1 absent;
    code(qpc_recovery_v1_epoch(handle,h.epoch_count,&absent,&e),&e,QPC_ARGUMENT);
    if (ferror(out)) bad("report formatting");
    if (fclose(out)) bad("report stream close");
    if (!length || length>1048576) bad("report size");
    retain(path,"c-loss-report",(const uint8_t *)bytes,length,create); free(bytes);
    qpc_closure_status_v1 current=status(handle);
    if (current.phase!=1 || memcmp(current.report,report,32)) bad("pending report identity");
}
int recovery_command(int argc,char **argv,const qpc_witness_v1 *witness) {
    if (argc<3 || argc>4) bad("recovery arguments");
    const char *mode=argv[1], *path=argv[2]; qpc_error_v1 e;
    if (!strcmp(mode,"recover-kind")) {
        if (argc!=3) bad("kind arguments");
        uint64_t live=0;
        int32_t result=witness ? qpc_owner_v1_open_witness((const uint8_t *)path,strlen(path),1,witness,&live,&e)
                              : qpc_owner_v1_open((const uint8_t *)path,strlen(path),1,&live,&e);
        code(result,&e,0);
        qpc_closure_header_v1 h; code(qpc_recovery_v1_begin(live,&h,&e),&e,QPC_OWNER_KIND);
        close_recovery(live); puts("operational-owner-not-recovery");
    } else {
        uint64_t handle=open_recovery(path,witness); uint32_t count=0;
        code(qpc_recovery_v1_session_count(handle,&count,&e),&e,0);
        if (!strcmp(mode,"recover-reject-select")) {
            if (argc!=4 || count!=1) bad("selection refusal setup");
            uint8_t session[32]; decode(argv[3],session);
            int32_t result=qpc_recovery_v1_select(handle,session,&e);
            if (!result) bad("required original witness was bypassed");
            code(result,&e,result);
            code(qpc_recovery_v1_session_count(handle,&count,&e),&e,QPC_DURABLE_CLOSED);
            printf("selection-refused:%d\n",result);
        } else if (!strcmp(mode,"recover-reject-archive")) {
            if (argc!=3 || count!=0) bad("archive refusal setup");
            size_t size=0; uint8_t *archive=read_file(path,"c-closure-archive",&size);
            int32_t result=qpc_recovery_v1_select_archive(handle,archive,size,&e);free(archive);
            if (!result) bad("closed archive bypassed original witness");
            code(result,&e,result);
            code(qpc_recovery_v1_session_count(handle,&count,&e),&e,QPC_DURABLE_CLOSED);
            printf("archive-refused:%d\n",result);
        } else if (!strcmp(mode,"recover-list")) {
            if (argc!=3) bad("list arguments");
            printf("catalogue:%u\n",count);
        } else if (!strcmp(mode,"recover-tamper")) {
            if (argc!=3 || count!=1) bad("tamper setup");
            size_t size=0; uint8_t *archive=read_file(path,"native-closure-archive",&size);
            if (size!=QPC_CLOSURE_ARCHIVE_BYTES) bad("archive size");
            code(qpc_recovery_v1_select_archive(handle,archive,size-1,&e),&e,QPC_ENCODING);
            code(qpc_recovery_v1_session_count(handle,&count,&e),&e,0);
            if (count!=1) bad("parse error consumed discovery");
            archive[size-1]^=1;
            code(qpc_recovery_v1_select_archive(handle,archive,size,&e),&e,QPC_IMAGE_AUTHENTICATION);
            free(archive);
            code(qpc_recovery_v1_session_count(handle,&count,&e),&e,QPC_DURABLE_CLOSED);
            puts("tampered-archive-refused");
        } else if (!strcmp(mode,"recover-archive")) {
            if (argc!=3 || count!=0) bad("archive recovery setup");
            size_t size=0; uint8_t *archive=read_file(path,"c-closure-archive",&size);
            code(qpc_recovery_v1_select_archive(handle,archive,size,&e),&e,0); free(archive);
            uint8_t report[32]; saved_id(path,report); qpc_closure_status_v1 s=status(handle);
            if (s.phase!=2 || memcmp(s.report,report,32)) bad("archive restored operational state");
            code(qpc_recovery_v1_restore_index(handle,&e),&e,0);
            code(qpc_recovery_v1_restore_index(handle,&e),&e,0);
            uint8_t removed=0; code(qpc_recovery_v1_retire(handle,report,&removed,&e),&e,0);
            if (removed!=1) bad("restored row not retired");
            code(qpc_recovery_v1_retire(handle,report,&removed,&e),&e,0);
            if (removed!=0) bad("absent row not independently validated");
            puts("archive-closed-metadata-only");
        } else {
            if (argc!=4 || count!=1) bad("session selection setup");
            uint8_t session[32],hint[32]; decode(argv[3],session);
            code(qpc_recovery_v1_session_at(handle,0,hint,&e),&e,0);
            if (memcmp(hint,session,32)) bad("catalogue hint differs");
            code(qpc_recovery_v1_session_at(handle,1,hint,&e),&e,QPC_ARGUMENT);
            if (!strcmp(mode,"recover-missing")) {
                session[31]^=1; code(qpc_recovery_v1_select(handle,session,&e),&e,QPC_DURABLE_ABSENT);
                code(qpc_recovery_v1_session_count(handle,&count,&e),&e,QPC_DURABLE_CLOSED);
                puts("missing-session-refused");
            } else {
                code(qpc_recovery_v1_select(handle,session,&e),&e,0);
                code(qpc_recovery_v1_select(handle,session,&e),&e,QPC_STATE);
                uint8_t archive[QPC_CLOSURE_ARCHIVE_BYTES];
                code(qpc_recovery_v1_archive(handle,archive,&e),&e,0);
                retain(path,"c-closure-archive",archive,sizeof(archive),1);
                uint8_t report[32];
                if (!strcmp(mode,"recover-cancel")) {
                    qpc_closure_status_v1 before=status(handle);
                    if (before.phase!=0) bad("cancellation fixture already frozen");
                    code(qpc_owner_v1_cancel(handle,&e),&e,0);
                    qpc_closure_header_v1 h;
                    code(qpc_recovery_v1_begin(handle,&h,&e),&e,QPC_CANCELLED);
                    if (witness) {
                        qpc_closure_status_v1 s;
                        code(qpc_recovery_v1_status(handle,&s,&e),&e,QPC_ANCHOR);
                    } else {
                        qpc_closure_status_v1 s=status(handle);
                        if (s.phase!=0) bad("cancelled cleanup froze the session");
                    }
                    code(qpc_recovery_v1_restore_index(handle,&e),&e,QPC_CANCELLED);
                    puts("cancelled-cleanup-not-frozen");
                } else if (!strcmp(mode,"recover-witness-failed-freeze")) {
                    if (!witness) bad("missing explicit witness");
                    qpc_closure_header_v1 h;
                    code(qpc_recovery_v1_begin(handle,&h,&e),&e,QPC_ANCHOR);
                    puts("witness-freeze-outcome-unavailable");
                } else if (!strcmp(mode,"recover-freeze")) {
                    snapshot(handle,path,1,report); exit(77);
                } else if (!strcmp(mode,"recover-ack-crash")) {
                    snapshot(handle,path,0,report);
                    uint8_t wrong[32]; memcpy(wrong,report,32); wrong[0]^=1;
                    code(qpc_recovery_v1_acknowledge(handle,wrong,&e),&e,QPC_SCOPE_CONFLICT);
                    qpc_closure_status_v1 s=status(handle);
                    if (s.phase!=1 || memcmp(s.report,report,32)) bad("wrong ACK changed closure");
                    code(qpc_recovery_v1_acknowledge(handle,report,&e),&e,0);
                    s=status(handle); if (s.phase!=2 || memcmp(s.report,report,32)) bad("ACK not closed");
                    qpc_closure_header_v1 h; code(qpc_recovery_v1_begin(handle,&h,&e),&e,QPC_RETIRED);
                    exit(77);
                } else if (!strcmp(mode,"recover-finish")) {
                    saved_id(path,report); qpc_closure_status_v1 s=status(handle);
                    if (s.phase!=2 || memcmp(s.report,report,32)) bad("unknown ACK not reconciled");
                    code(qpc_recovery_v1_acknowledge(handle,report,&e),&e,0);
                    uint8_t removed=0; code(qpc_recovery_v1_retire(handle,report,&removed,&e),&e,0);
                    if (removed!=1) bad("original catalogue row not retired");
                    code(qpc_recovery_v1_retire(handle,report,&removed,&e),&e,0);
                    if (removed) bad("already absent row changed");
                    puts("original-report-closed-retired");
                } else bad("unknown recovery mode");
            }
        }
        close_recovery(handle);
    }
    if (ferror(stdout) || fflush(stdout)) bad("recovery output flush");
    return 0;
}
