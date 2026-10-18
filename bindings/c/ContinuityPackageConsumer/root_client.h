/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_ROOT_CLIENT_H
#define QPC_ROOT_CLIENT_H
#include "qpc_owner.h"
#include "client_inputs.h"
#include <errno.h>
#ifdef _WIN32
#include "private_files_windows.h"
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include "consumer_platform.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define QPC_ROOT_REPORT_LIMIT ((size_t)8388608)

static _Noreturn void fail(const char *message) {
    fprintf(stderr,"root C failure: %s\n",message);exit(1);
}
static void expect(int32_t code,int32_t wanted,const qpc_error_v1 *error) {
    if(code!=wanted || error->code!=code || error->length>sizeof error->message ||
       error->truncated>1 || ((code==0)!=(error->length==0))) {
        fprintf(stderr,"root C code=%d expected=%d diagnostic=%.*s\n",code,wanted,
                (int)(error->length<=sizeof error->message ? error->length : 0),error->message);
        fail("native outcome");
    }
}
static void require_at(int32_t code,const qpc_error_v1 *error,const char *file,int line) {
    if(code) fprintf(stderr,"root C call failed at %s:%d\n",file,line);
    expect(code,0,error);
}
#define require(code,error) require_at((code),(error),__FILE__,__LINE__)
static void close_owner(uint64_t handle) {
    qpc_error_v1 error;require(qpc_owner_v1_close(handle,&error),&error);
}
static void path_join(char out[4096],const char *path,const char *name) {
    int n=snprintf(out,4096,"%s/%s",path,name);
    if(n<=0 || n>=4096) fail("path length");
}
static void save(const char *path,const char *name,const uint8_t *bytes,size_t length) {
#ifdef _WIN32
    int created=0;
    if(qpc_file_commit_bounded(path,name,bytes,length,QPC_ROOT_REPORT_LIMIT,&created) || !created)
        fail("exclusive public output");
#else
    char file[4096];path_join(file,path,name);
    int fd=open(file,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0) fail("exclusive public output");
    size_t used=0;
    while(used<length) {
        ssize_t n=write(fd,bytes+used,length-used);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) fail("public output write");
        used+=(size_t)n;
    }
    if(fsync(fd) || close(fd)) fail("public output sync");
    fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0 || fsync(fd) || close(fd)) fail("public directory sync");
#endif
}
static void save_number(const char *path,const char *name,uint64_t value) {
    uint8_t wire[8];for(size_t i=0;i<8;i++) wire[7-i]=(uint8_t)(value>>(8*i));
    save(path,name,wire,sizeof wire);
}
static uint64_t counter(const uint8_t *bytes) {
    uint64_t value=0;for(size_t i=0;i<8;i++) value=(value<<8)|bytes[i];return value;
}
static qpc_enrollment_intent_v1 read_intent(const char *path,uint8_t root[1985]) {
    uint8_t wire[72];
    if(fixed(path,"enrollment-root",root,1985) || fixed(path,"enrollment-intent",wire,sizeof wire)) fail("original intent");
    qpc_enrollment_intent_v1 intent={.root=root,.root_length=1985,.generation=counter(wire+16),
        .valid_from=counter(wire+56),.valid_until=counter(wire+64)};
    memcpy(intent.device,wire,16);memcpy(intent.family,wire+24,32);return intent;
}
typedef struct {
    qpc_authority_options_v1 registry;
    qpc_root_scope_v1 scope;
    uint8_t witness[1985],original_root[1985],target_root[1985];
    uint8_t plan[131072],receipt[131072],proposal[65536];
    size_t plan_length;
    qpc_enrollment_intent_v1 original,target;
} root_inputs;
static void read_inputs(root_inputs *in,const char *public,const char *old,const char *target) {
    in->registry.struct_size=sizeof in->registry;in->scope.struct_size=sizeof in->scope;
    if(fixed(public,"registry-id",in->registry.identity,32) || fixed(public,"family",in->registry.family,32) ||
       fixed(public,"witness-id",in->registry.witness,32) || fixed(public,"witness-public",in->witness,sizeof in->witness) ||
       fixed(public,"application",in->scope.checkpoint.application,32) || fixed(public,"account",in->scope.checkpoint.account,32) ||
       number(public,"revision",&in->scope.checkpoint.revision) ||
       load(public,"approved-plan",in->plan,sizeof in->plan,&in->plan_length)) fail("independent root approval");
    in->registry.public_key=in->witness;in->registry.public_key_length=sizeof in->witness;
    memcpy(in->scope.witness,in->registry.witness,32);
    in->scope.public_key=in->witness;in->scope.public_key_length=sizeof in->witness;
    in->original=read_intent(old,in->original_root);in->target=read_intent(target,in->target_root);
}
static uint64_t open_registry(const char *path,const root_inputs *in) {
    uint64_t handle=0;qpc_error_v1 error;
    require(qpc_authority_v1_prepare_open((const uint8_t *)path,strlen(path),&in->registry,&handle,&error),&error);
    require(qpc_owner_v1_finish_open(handle,&error),&error);return handle;
}
static uint64_t open_enrollment(const char *path,const qpc_enrollment_intent_v1 *intent,
                               const qpc_witness_v1 *witness,const root_inputs *in,uint64_t registry) {
    uint64_t handle=0;qpc_error_v1 error;
    qpc_open_options_v1 options={3,0,1,witness};
    if(registry) {
        qpc_authority_enrollment_options_v1 selected={sizeof selected,0,registry,in->scope.checkpoint,intent,&options};
        require(qpc_authority_v1_prepare_enrollment((const uint8_t *)path,strlen(path),&selected,&handle,&error),&error);
    } else require(qpc_enrollment_v1_prepare_resume((const uint8_t *)path,strlen(path),intent,&options,&handle,&error),&error);
    require(qpc_owner_v1_finish_open(handle,&error),&error);return handle;
}
static void active(uint64_t handle,uint8_t id[32]) {
    qpc_error_v1 error;require(qpc_device_v1_next_publication(handle,id,&error),&error);
    uint8_t zero[32]={0};if(!memcmp(id,zero,32)) fail("live successor identity missing");
}
static void pause_for_kill(const char *path,const char *mode) {
    char name[128];int n=snprintf(name,sizeof name,"cut-%s",mode);
    if(n<=0 || (size_t)n>=sizeof name) fail("cut name");
#ifdef _WIN32
    /* The pinned publisher exposes the complete PID in one no-replace rename.
     * This marks a process cut after the SDK call, not a power-loss experiment. */
    save_number(path,name,qpc_process_id());
#else
    char pending[128],source[4096],destination[4096];
    n=snprintf(pending,sizeof pending,".ready-%s",mode);
    if(n<=0 || (size_t)n>=sizeof pending) fail("pending cut name");
    save_number(path,pending,qpc_process_id());
    path_join(source,path,pending);path_join(destination,path,name);
    /* The observer sees the complete file atomically, never a create-before-write prefix. */
    if(link(source,destination)) fail("atomic cut publication");
#endif
    struct timespec tick={0,10000000};
    for(unsigned i=0;i<3000;i++) if(qpc_sleep(&tick) && errno!=EINTR) fail("cut wait");
    fail("owned process was not killed within the bounded cut window");
}
#endif
