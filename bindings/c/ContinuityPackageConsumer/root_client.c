/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#include "root_client.h"
#include "root_cleanup_client.c"
#include "root_traffic_client.c"

static int execute(int argc,char **argv) {
    if(argc<2) fail("root mode required");
    int traffic=!strncmp(argv[1],"traffic-",8);
    if(argc!=(traffic ? 9 : 7)) fail("root inputs and optional traffic peer required");
    const char *mode=argv[1],*public=argv[2],*old=argv[3],*target=argv[4],*registry_path=argv[5];
    root_inputs *in=calloc(1,sizeof *in);if(!in) fail("bounded public input allocation");
    read_inputs(in,public,old,target);
    char marker[128];int n=snprintf(marker,sizeof marker,"process-%s",mode);
    if(n<=0 || (size_t)n>=sizeof marker) fail("process label");
    save_number(public,marker,(uint64_t)getpid());
#ifdef __APPLE__
    n=snprintf(marker,sizeof marker,"stack-%s",mode);if(n<=0 || (size_t)n>=sizeof marker) fail("stack label");
    save_number(public,marker,(uint64_t)pthread_get_stacksize_np(pthread_self()));
    pthread_attr_t defaults;size_t requested=0;
    if(pthread_attr_init(&defaults) || pthread_attr_getstacksize(&defaults,&requested) ||
       pthread_attr_destroy(&defaults) || !requested) fail("system default pthread stack");
    n=snprintf(marker,sizeof marker,"stack-default-%s",mode);if(n<=0 || (size_t)n>=sizeof marker) fail("default stack label");
    save_number(public,marker,(uint64_t)requested);
#endif
    uint64_t root=open_registry(registry_path,in),device=0;qpc_error_v1 error;
    if(!strcmp(mode,"traffic-authorize-peer")) {
        root_authorize_peer(root,public,argv[7],in->registry.family);
        close_owner(root);free(in);puts("root-stage-pass:traffic-authorize-peer");return 0;
    }
    qpc_witness_v1 witness={(const uint8_t *)argv[6],strlen(argv[6]),3000};
    if(!strcmp(mode,"begin")) {
        device=open_enrollment(old,&in->original,&witness,in,root);
        require(qpc_enrollment_v1_activate(device,&error),&error);
        require(qpc_root_v1_begin(root,device,&in->scope,in->plan,in->plan_length,&error),&error);
        uint8_t rejected[32];expect(qpc_device_v1_next_publication(device,rejected,&error),QPC_CLOSED,&error);
        close_owner(device);device=0;
    } else require(qpc_root_v1_resume(root,(const uint8_t *)old,strlen(old),&in->original,&in->scope,
                                     in->plan,in->plan_length,&error),&error);
    uint32_t state=0;require(qpc_root_v1_state(root,&state,&error),&error);
    if(!strcmp(mode,"begin") || !strcmp(mode,"preparing")) {
        if(state!=1) fail("original preparation missing");
    } else if(!strcmp(mode,"freeze") || !strcmp(mode,"freeze-retry")) {
        size_t length=0;if(load(public,"freeze-receipt",in->receipt,sizeof in->receipt,&length)) fail("freeze receipt");
        size_t written=0;require(qpc_root_v1_bind_freeze(root,in->receipt,length,in->proposal,sizeof in->proposal,&written,&error),&error);
        if(!strcmp(mode,"freeze")) save(public,"bound-proposal",in->proposal,written);
        else {
            size_t expected=0;if(load(public,"bound-proposal",in->receipt,sizeof in->receipt,&expected) ||
                expected!=written || memcmp(in->receipt,in->proposal,written)) fail("proposal identity changed on retry");
        }
    } else if(!strcmp(mode,"retain") || !strcmp(mode,"retain-retry")) {
        size_t length=0;if(load(public,"retirement-receipt",in->receipt,sizeof in->receipt,&length)) fail("retirement receipt");
        qpc_authority_checkpoint_v1 next;require(qpc_root_v1_retain_retirement(root,in->receipt,length,&next,&error),&error);
        uint8_t account[32];if(fixed(public,"target-account",account,32) || memcmp(next.account,account,32) ||
            memcmp(next.application,in->scope.checkpoint.application,32) || next.revision!=in->scope.checkpoint.revision+1) fail("successor mapping");
    } else {
        if(state!=3) fail("cleanup without committed original");
        device=open_enrollment(target,&in->target,&witness,in,0);
        if(!strcmp(mode,"activation-unknown")) {
            expect(qpc_root_v1_activate_successor(root,device,&error),QPC_ANCHOR,&error);
            uint32_t untouched=99;
            expect(qpc_root_v1_state(root,&untouched,&error),QPC_CLOSED,&error);
            if(untouched!=99) fail("failed activation released state");
            uint8_t rejected[32];expect(qpc_device_v1_next_publication(device,rejected,&error),QPC_CLOSED,&error);
            close_owner(device);close_owner(root);free(in);
            puts("root-stage-pass:activation-unknown");return 0;
        }
        require(qpc_root_v1_activate_successor(root,device,&error),&error);
        if(traffic) root_traffic(device,public,mode,argv[7],argv[8]);
        else {
            uint8_t before[32],after[32];active(device,before);
            cleanup(root,in,public,mode);active(device,after);
            if(memcmp(before,after,32)) fail("query or historical cleanup changed publication identity");
        }
    }
    if(!strcmp(mode,"begin") || !strcmp(mode,"freeze") || !strcmp(mode,"retain") ||
       !strcmp(mode,"inventory") || !strcmp(mode,"report") || !strcmp(mode,"prepare-ack") ||
       !strcmp(mode,"journal") || !strcmp(mode,"signer")) pause_for_kill(public,mode);
    close_owner(root);
    if(device) {
        uint8_t rejected[32];memset(rejected,99,sizeof rejected);
        expect(qpc_device_v1_next_publication(device,rejected,&error),QPC_DURABLE_CLOSED,&error);
        for(size_t i=0;i<sizeof rejected;i++) if(rejected[i]) fail("closed controller released identity");
        close_owner(device);
    }
    free(in);printf("root-stage-pass:%s\n",mode);return 0;
}
typedef struct { int argc;char **argv;int result; } invocation;
static void *run(void *context) {
    invocation *call=context;call->result=execute(call->argc,call->argv);return NULL;
}
int main(int argc,char **argv) {
    invocation call={argc,argv,1};pthread_t thread;
    if(pthread_create(&thread,NULL,run,&call) || pthread_join(thread,NULL)) return 1;
    return call.result;
}
