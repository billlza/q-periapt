/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Exercise the actual qualification client against owned and borrowed models. */
#define _GNU_SOURCE 1
#include "qpc_owner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Noreturn void fail(const char *message) {
    fprintf(stderr,"lifetime control: %s\n",message);
    exit(1);
}
static void record(int32_t code,const qpc_error_v1 *error) {
    if(error->code!=code) fail("diagnostic mismatch");
}
static void require(int32_t code,const qpc_error_v1 *error) {
    record(code,error);
    if(code) fail("borrowed caller input rejected");
}
static size_t enrollment_read(const char *path,const char *name,uint8_t *out,size_t maximum) {
    (void)path;(void)name;
    memset(out,0x5a,maximum);
    return maximum;
}
static void enrollment_exact(const char *path,const char *name,uint8_t *out,size_t length) {
    (void)enrollment_read(path,name,out,length);
}
static uint64_t enrollment_counter(const uint8_t bytes[8]) {
    uint64_t value=0;
    for(size_t i=0;i<8;++i) value=(value<<8)|bytes[i];
    return value;
}

#include "peer_configuration_client.c"

struct Region { const uint8_t *caller; uint8_t *copy; size_t length; };
static struct Region regions[7];
static unsigned region_count, borrowed;
static void remember(const void *bytes,size_t length) {
    if(region_count>=7 || !bytes || !length) fail("invalid model region");
    struct Region *region=&regions[region_count++];
    region->caller=bytes;region->length=length;region->copy=malloc(length);
    if(!region->copy) fail("model allocation");
    memcpy(region->copy,bytes,length);
}
static int32_t prepare_model(uint64_t parent,const qpc_peer_configuration_v1 *input,
                             const uint8_t *session,uint64_t *handle,qpc_error_v1 *error) {
    memset(error,0,sizeof(*error));
    if(!parent) { *handle=0;error->code=QPC_ARGUMENT;return QPC_ARGUMENT; }
    if(parent!=17 || region_count || !input) fail("unexpected preparation");
    remember(input->initiator.account.root,input->initiator.account.root_length);
    remember(input->responder.account.root,input->responder.account.root_length);
    remember(input->bundle.data,input->bundle.length);
    remember(input->tls_peer.data,input->tls_peer.length);
    remember(input->tls_name.data,input->tls_name.length);
    remember(input,sizeof(*input));
    if(session) remember(session,32);
    *handle=19;
    return 0;
}
int32_t qpc_peer_v1_prepare_configured(uint64_t parent,const qpc_peer_configuration_v1 *input,
                                     uint64_t *handle,qpc_error_v1 *error) {
    return prepare_model(parent,input,NULL,handle,error);
}
int32_t qpc_peer_v1_prepare_configured_reopen(uint64_t parent,const qpc_peer_configuration_v1 *input,
                                            const uint8_t session[32],uint64_t *handle,qpc_error_v1 *error) {
    return prepare_model(parent,input,session,handle,error);
}
int32_t qpc_owner_v1_finish_open(uint64_t handle,qpc_error_v1 *error) {
    if(handle!=19 || !region_count || borrowed>region_count) fail("unexpected finish");
    memset(error,0,sizeof(*error));
    for(unsigned i=0;i<region_count;++i) {
        const struct Region *region=&regions[i];
        const volatile uint8_t *caller=region->caller;
        for(size_t j=0;j<region->length;++j)
            if(caller[j]) fail("caller allocation was not overwritten before finish");
        const uint8_t *selected=borrowed==i+1 ? region->caller : region->copy;
        if(memcmp(selected,region->copy,region->length)) error->code=777;
    }
    return error->code;
}
int main(int argc,char **argv) {
    if(argc!=3) fail("arguments");
    borrowed=(unsigned)strtoul(argv[1],NULL,10);
    unsigned reopen=(unsigned)strtoul(argv[2],NULL,10);
    uint8_t session[32];memset(session,0x37,sizeof(session));
    if(reopen>1 || borrowed>6+reopen) fail("model selection");
    if(configured_peer_guard()) fail("header guard");
    if(configured_device_peer_open(17,"public-fixture",1,reopen ? session : NULL)!=19)
        fail("handle changed");
    for(unsigned i=0;i<region_count;++i) free(regions[i].copy);
    puts("PEER_CONFIGURATION_LIFETIME_PASS");
    return 0;
}
