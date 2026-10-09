/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Qualification client only. Public fixtures model independently supplied trust;
 * the SDK receives owned copies and never receives the fixture directory. */
#include <sys/mman.h>
_Static_assert(sizeof(qpc_peer_device_v1) == 144, "peer device ABI size");
_Static_assert(sizeof(qpc_peer_configuration_v1) == 384, "peer configuration ABI size");
_Static_assert(offsetof(qpc_peer_configuration_v1, initiator) == 16, "peer initiator ABI");
_Static_assert(offsetof(qpc_peer_configuration_v1, responder) == 160, "peer responder ABI");
_Static_assert(offsetof(qpc_peer_configuration_v1, directory) == 304, "peer directory ABI");
_Static_assert(offsetof(qpc_peer_configuration_v1, bundle) == 336, "peer bundle ABI");
_Static_assert(offsetof(qpc_peer_configuration_v1, tls_name) == 368, "peer TLS name ABI");
static void peer_config_exact(const char *path, const char *prefix, const char *leaf,
                              uint8_t *output, size_t length) {
    char name[128];
    int n=snprintf(name,sizeof(name),"%s-%s",prefix,leaf);
    if(n<0 || (size_t)n>=sizeof(name)) fail("peer input name");
    enrollment_exact(path,name,output,length);
}
static qpc_peer_device_v1 peer_config_device(const char *path, const char *prefix,
                                            uint8_t root[1985]) {
    qpc_peer_device_v1 device={0}; uint8_t counter[8];
    peer_config_exact(path,prefix,"root",root,1985);
    device.account.root=root; device.account.root_length=1985;
    peer_config_exact(path,prefix,"account",device.account.account,32);
    enrollment_exact(path,"family",device.account.family,32);
    peer_config_exact(path,prefix,"roster-version",counter,8);
    device.account.checkpoint.version=enrollment_counter(counter);
    peer_config_exact(path,prefix,"roster-digest",device.account.checkpoint.digest,32);
    peer_config_exact(path,prefix,"device",device.device,16);
    peer_config_exact(path,prefix,"generation",counter,8);
    device.generation=enrollment_counter(counter);
    return device;
}
static uint64_t configured_device_peer_open(uint64_t parent,const char *path,
                                            uint32_t role,const uint8_t *existing) {
    uint8_t left[1985],right[1985],bundle[65536],certificate[8192],name[128],session[32]={0};
    qpc_peer_configuration_v1 input={0};
    input.header=(qpc_configuration_header_v1){sizeof(input),1};
    input.quality=1; input.role=role;
    input.initiator=peer_config_device(path,"initiator",left);
    input.responder=peer_config_device(path,"responder",right);
    enrollment_exact(path,"directory",input.directory,32);
    input.bundle=(qpc_configuration_blob_v1){bundle,enrollment_read(path,"bootstrap.bundle",bundle,sizeof(bundle))};
    input.tls_peer=(qpc_configuration_blob_v1){certificate,enrollment_read(path,"tls-peer",certificate,sizeof(certificate))};
    input.tls_name=(qpc_configuration_blob_v1){name,enrollment_read(path,"tls-peer-name",name,sizeof(name))};
    if(existing) memcpy(session,existing,sizeof(session));
    uint64_t handle=0; qpc_error_v1 error;
    int32_t code=existing ? qpc_peer_v1_prepare_configured_reopen(parent,&input,session,&handle,&error) :
        qpc_peer_v1_prepare_configured(parent,&input,&handle,&error);
    require(code,&error);
    if(!handle) fail("configured peer pending handle");
    /* All buffers stay live but change before finish; a borrowed-pointer bug
     * cannot be hidden by unchanged allocator storage. These are public values. */
    memset(left,0,sizeof(left));memset(right,0,sizeof(right));memset(bundle,0,sizeof(bundle));
    memset(certificate,0,sizeof(certificate));memset(name,0,sizeof(name));
    memset(session,0,sizeof(session));memset(&input,0,sizeof(input));
    require(qpc_owner_v1_finish_open(handle,&error),&error);
    return handle;
}
static void peer_config_reject(const void *input) {
    qpc_error_v1 error;uint64_t handle=99;uint8_t session[32]={1};
    int32_t code=qpc_peer_v1_prepare_configured(0,input,&handle,&error);
    record(code,&error);
    if(code!=QPC_ARGUMENT || handle) fail("short peer configuration admitted");
    handle=99;
    code=qpc_peer_v1_prepare_configured_reopen(0,input,session,&handle,&error);
    record(code,&error);
    if(code!=QPC_ARGUMENT || handle) fail("short peer reopen configuration admitted");
}
static int configured_peer_guard(void) {
    long page=sysconf(_SC_PAGESIZE);if(page<=0) fail("page size unavailable");
    size_t length=(size_t)page*2;
    uint8_t *memory=mmap(NULL,length,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(memory==MAP_FAILED) fail("guard mapping");
    if(mprotect(memory+page,(size_t)page,PROT_NONE)) fail("guard protection");
    uint32_t *size=(void *)(memory+page-4);*size=4;
    peer_config_reject(size); /* Only the first four bytes are readable. */
    qpc_configuration_header_v1 *header=(void *)(memory+page-8);
    *header=(qpc_configuration_header_v1){8,1};peer_config_reject(header);
    *header=(qpc_configuration_header_v1){sizeof(qpc_peer_configuration_v1),2};peer_config_reject(header);
    *header=(qpc_configuration_header_v1){sizeof(qpc_peer_configuration_v1)+8,1};peer_config_reject(header);
    peer_config_reject(NULL);
    if(munmap(memory,length)) fail("guard unmap");
    puts("QPC_PEER_CONFIGURATION_HEADER_GUARD_PASS");
    return 0;
}
