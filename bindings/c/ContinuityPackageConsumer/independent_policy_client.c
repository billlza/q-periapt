/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Same-platform fixture serialization only; these ABI records are not network messages. */
_Static_assert(sizeof(qpc_policy_renewal_scope_v1)==320,"independent scope size");
_Static_assert(offsetof(qpc_policy_renewal_scope_v1,current_roster)==160,"scope roster");
_Static_assert(offsetof(qpc_policy_renewal_scope_v1,previous_authorization)==280,"scope authorization");
_Static_assert(sizeof(qpc_public_record_v1)==8196,"public record size");
_Static_assert(sizeof(qpc_policy_renewal_request_v1)==33176,"independent request size");
_Static_assert(offsetof(qpc_policy_renewal_request_v1,original_roster_checkpoint)==352,"original checkpoint offset");
_Static_assert(offsetof(qpc_policy_renewal_request_v1,original_credential)==392,"original credential offset");
_Static_assert(sizeof(qpc_policy_renewal_status_v1)==160,"independent status size");
_Static_assert(offsetof(qpc_policy_renewal_status_v1,target)==72,"policy target offset");
_Static_assert(offsetof(qpc_policy_renewal_status_v1,observed_at)==152,"policy time offset");
static void independent_status_print(const qpc_policy_renewal_status_v1 *s) {
    printf("%u\n%u\n",s->phase,s->reason);encode(s->operation);encode(s->statement);
    printf("%llu\n",(unsigned long long)s->target.version);encode(s->target.digest);
    printf("%llu\n",(unsigned long long)s->observed_roster.version);encode(s->observed_roster.digest);
    printf("%llu\n",(unsigned long long)s->observed_at);
}
typedef struct {
    uint64_t handle;
    const uint8_t *operation;
    qpc_policy_renewal_request_v1 *request;
    qpc_error_v1 *error;
    int witnessed;
    int32_t code;
} independent_request_call;
static void *independent_request_worker(void *opaque) {
    independent_request_call *call=opaque;
    call->code=call->witnessed ?
        qpc_enrollment_v1_witnessed_policy_renewal_request(call->handle,call->operation,call->request,call->error) :
        qpc_enrollment_v1_policy_renewal_request(call->handle,call->operation,call->request,call->error);
    return NULL;
}
/* Real public requests on a default foreign pthread. Inputs/output stay owned
 * by the calling frame until join; no stack-size override or detached worker. */
static int32_t independent_request_on_worker(uint64_t handle,const uint8_t operation[32],
    qpc_policy_renewal_request_v1 *request,qpc_error_v1 *error,int witnessed) {
    independent_request_call call={handle,operation,request,error,witnessed,-1};
    pthread_t worker;
    if(pthread_create(&worker,NULL,independent_request_worker,&call)) fail("policy request worker creation");
    if(pthread_join(worker,NULL)) fail("policy request worker join");
    return call.code;
}
static uint64_t independent_policy_parent(const char *path,const qpc_witness_v1 *witness,int tls) {
    uint64_t handle=enrollment_open(path,0,witness,tls);qpc_error_v1 error;
    char target_path[4096];enrollment_path(target_path,path,"independent-sdk");
    uint8_t root[1985],wire[8192];qpc_policy_document_v1 target=policy_document(target_path,root,wire);
    require(qpc_enrollment_v1_select_continued_policy(handle,(const uint8_t *)target_path,strlen(target_path),&target,&error),&error);
    require(qpc_enrollment_v1_activate_policy_renewal(handle,&error),&error);return handle;
}
#include "witnessed_independent_policy_client.c"
static int independent_policy_command(uint64_t handle,const char *path,const char *mode) {
    if(!strncmp(mode,"witness-",8)) return witnessed_independent_policy_command(handle,path,mode+8);
    qpc_error_v1 error;
    uint8_t operation[32];enrollment_exact(path,"independent-operation",operation,32);
    qpc_policy_renewal_status_v1 status;memset(&status,0xa5,sizeof(status));
    if(!strcmp(mode,"request") || !strcmp(mode,"request-refused")) {
        qpc_policy_renewal_request_v1 request;memset(&request,0xa5,sizeof(request));
        int32_t code=independent_request_on_worker(handle,operation,&request,&error,0);record(code,&error);
        if(!strcmp(mode,"request-refused")) {
            if(code!=QPC_SUSPENDED) fail("pending policy accepted a replacement request");
            const uint8_t *bytes=(const uint8_t *)&request;for(size_t i=0;i<sizeof(request);i++) if(bytes[i]!=0xa5) fail("failed request published bytes");
            qpc_enrollment_status_v1 owner;code=qpc_enrollment_v1_status(handle,&owner,&error);record(code,&error);
            if(code!=QPC_CLOSED) fail("failed request retained usable owner");
            close_owner(handle);puts("request-refused:215");return 0;
        }
        require(code,&error);
        enrollment_write(path,"independent-request",(const uint8_t *)&request,sizeof(request));
        close_owner(handle);puts("request-saved");return 0;
    }
    if(!strcmp(mode,"status")) {
        require(qpc_enrollment_v1_policy_renewal_status(handle,&status,&error),&error);
    } else if(!strcmp(mode,"pending")) {
        qpc_public_record_v1 result;uint8_t first[8192];size_t length=enrollment_read(path,"independent-first-approvals",first,sizeof(first));
        require(qpc_enrollment_v1_pending_policy_renewal_approval(handle,operation,&result,&error),&error);
        if(result.length!=length || memcmp(result.bytes,first,length)) fail("pending changed first original signatures");
        for(size_t i=length;i<sizeof(result.bytes);i++) if(result.bytes[i]) fail("pending leaked unused output bytes");
        close_owner(handle);puts("pending-exact");return 0;
    } else {
        char target_path[4096];enrollment_path(target_path,path,"independent-sdk");
        uint8_t target_root[1985],target_wire[8192];qpc_policy_document_v1 target=policy_document(target_path,target_root,target_wire);
        if(!strcmp(mode,"resolve") || !strcmp(mode,"resolve-pending") || !strcmp(mode,"resolve-conflict") ||
           !strcmp(mode,"resolve-scope") || !strcmp(mode,"resolve-cancelled")) {
            uint8_t statement[32];enrollment_exact(path,"independent-statement",statement,32);
            int32_t expected=!strcmp(mode,"resolve-pending") ? QPC_SUSPENDED : !strcmp(mode,"resolve-conflict") ? QPC_SCOPE_CONFLICT :
                !strcmp(mode,"resolve-scope") ? QPC_SCOPE : !strcmp(mode,"resolve-cancelled") ? QPC_CANCELLED : QPC_OK;
            if(expected==QPC_CANCELLED) require(qpc_owner_v1_cancel(handle,&error),&error);
            int32_t code=qpc_enrollment_v1_resolve_policy_renewal(handle,operation,statement,&target,&status,&error);record(code,&error);
            if(expected!=QPC_OK) {
                if(code!=expected) fail("historical lookup refused for another reason");
                const uint8_t *bytes=(const uint8_t *)&status;for(size_t i=0;i<sizeof(status);i++) if(bytes[i]!=0xa5) fail("unresolved lookup published status");
                qpc_enrollment_status_v1 original;
                code=qpc_enrollment_v1_status(handle,&original,&error);record(code,&error);
                if(code!=(expected==QPC_CANCELLED ? QPC_CANCELLED : QPC_CLOSED)) fail("historical refusal ownership differs");
                close_owner(handle);
                if(expected==QPC_SUSPENDED) puts("pending-unresolved:215");
                else printf("policy-resolve-refused:%d\n",expected);
                return 0;
            }
            require(code,&error);
        } else {
            require(qpc_enrollment_v1_select_continued_policy(handle,(const uint8_t *)target_path,strlen(target_path),&target,&error),&error);
            if(!strcmp(mode,"reconcile")) {
                require(qpc_enrollment_v1_reconcile_policy_renewal(handle,&status,&error),&error);
            } else if(!strcmp(mode,"activate")) {
                require(qpc_enrollment_v1_activate_policy_renewal(handle,&error),&error);
                int32_t code=qpc_enrollment_v1_policy_renewal_status(handle,&status,&error);record(code,&error);
                if(code!=QPC_OWNER_KIND) fail("independent activation did not transfer original owner");
                close_owner(handle);puts("independent-device-active");return 0;
            } else {
                qpc_policy_renewal_request_v1 request;enrollment_exact(path,"independent-request",(uint8_t *)&request,sizeof(request));
                uint8_t root[1985];qpc_enrollment_intent_v1 intent=enrollment_intent(path,root);
                qpc_account_pin_v1 pin={.root=root,.root_length=sizeof(root)};
                memcpy(pin.family,intent.family,32);enrollment_exact(path,"trusted-account",pin.account,32);
                uint8_t version[8];enrollment_exact(path,"trusted-roster-version",version,8);pin.checkpoint.version=enrollment_counter(version);
                enrollment_exact(path,"trusted-roster-digest",pin.checkpoint.digest,32);
                uint8_t approvals[8192];size_t length=enrollment_read(path,"independent-approvals",approvals,sizeof(approvals));
                uint8_t previous_root[1985],previous_wire[8192];qpc_policy_document_v1 previous=policy_document(path,previous_root,previous_wire);
                int32_t expected=QPC_OK;
                if(!strcmp(mode,"stage-corrupt-scope")) {request.scope.operation[0]^=1;expected=QPC_SCOPE;}
                else if(!strcmp(mode,"stage-corrupt-certificate")) {request.original_credential.bytes[request.original_credential.length-1]^=1;expected=QPC_AUTHENTICATION;}
                else if(!strcmp(mode,"stage-dirty-tail")) {request.original_credential.bytes[8191]=1;expected=QPC_ARGUMENT;}
                else if(!strcmp(mode,"stage-cancelled")) {require(qpc_owner_v1_cancel(handle,&error),&error);expected=QPC_CANCELLED;}
                else if(strcmp(mode,"stage")) fail("unknown independent policy mode");
                int32_t code=qpc_enrollment_v1_stage_policy_renewal(handle,&request,&pin,&pin,approvals,length,&previous,&status,&error);record(code,&error);
                if(code!=expected) {require(code,&error);fail("expected independent stage refusal");}
                if(expected!=QPC_OK) {
                    const uint8_t *bytes=(const uint8_t *)&status;for(size_t i=0;i<sizeof(status);i++) if(bytes[i]!=0xa5) fail("failed stage published output");
                    if(expected!=QPC_CANCELLED) {
                        qpc_enrollment_status_v1 owner;code=qpc_enrollment_v1_status(handle,&owner,&error);record(code,&error);
                        if(code!=(expected==QPC_ARGUMENT ? QPC_OK : QPC_CLOSED)) fail("stage error ownership differs");
                    }
                    close_owner(handle);printf("stage-refused:%d\n",expected);return 0;
                }
            }
        }
    }
    independent_status_print(&status);close_owner(handle);return 0;
}
