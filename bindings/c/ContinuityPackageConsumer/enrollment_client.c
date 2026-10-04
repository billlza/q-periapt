/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Qualification client only: authority grants are independent public inputs. */
_Static_assert(sizeof(qpc_enrollment_intent_v1)==88,"enrollment intent ABI");
_Static_assert(sizeof(qpc_account_pin_v1)==120,"account pin ABI");
_Static_assert(sizeof(qpc_enrollment_status_v1)==152,"enrollment status ABI");
_Static_assert(offsetof(qpc_enrollment_status_v1,previous)==72,"checkpoint ABI alignment");
_Static_assert(sizeof(qpc_enrollment_request_v1)==8196,"request ABI");
_Static_assert(sizeof(qpc_credential_renewal_status_v1)==120,"credential renewal status ABI");
_Static_assert(offsetof(qpc_credential_renewal_status_v1,checkpoint)==72,"renewal checkpoint ABI");
_Static_assert(offsetof(qpc_credential_renewal_status_v1,observed_at)==112,"renewal observation ABI");
static void enrollment_path(char out[4096],const char *path,const char *name) {
    int n=snprintf(out,4096,"%s/%s",path,name);
    if(n<=0 || n>=4096) fail("enrollment test path");
}
static size_t enrollment_read(const char *path,const char *name,uint8_t *out,size_t maximum) {
    char file[4096];enrollment_path(file,path,name);
    int fd=open(file,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat st;
    if(fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<=0 ||
       (uint64_t)st.st_size>maximum) fail("enrollment public input");
    size_t length=(size_t)st.st_size,used=0;
    while(used<length) {
        ssize_t n=read(fd,out+used,length-used);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) fail("enrollment public read");
        used+=(size_t)n;
    }
    if(close(fd)) fail("enrollment public close");
    return length;
}
static void enrollment_exact(const char *path,const char *name,uint8_t *out,size_t length) {
    if(enrollment_read(path,name,out,length)!=length) fail("enrollment input width");
}
static void enrollment_write(const char *path,const char *name,const uint8_t *bytes,size_t length) {
    char file[4096];enrollment_path(file,path,name);
    int fd=open(file,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0) fail("enrollment public output");
    size_t used=0;
    while(used<length) {
        ssize_t n=write(fd,bytes+used,length-used);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) fail("enrollment public write");
        used+=(size_t)n;
    }
    if(fsync(fd) || close(fd)) fail("enrollment output sync");
}
static uint64_t enrollment_counter(const uint8_t bytes[8]) {
    uint64_t n=0;for(size_t i=0;i<8;i++) n=(n<<8)|bytes[i];return n;
}
static qpc_enrollment_intent_v1 enrollment_intent(const char *path,uint8_t root[1985]) {
    uint8_t bytes[72];enrollment_exact(path,"enrollment-root",root,1985);
    enrollment_exact(path,"enrollment-intent",bytes,sizeof(bytes));
    qpc_enrollment_intent_v1 intent={.root=root,.root_length=1985,
        .generation=enrollment_counter(bytes+16),.valid_from=enrollment_counter(bytes+56),
        .valid_until=enrollment_counter(bytes+64)};
    memcpy(intent.device,bytes,16);memcpy(intent.family,bytes+24,32);return intent;
}
static uint64_t enrollment_prepare(const char *path,int create,const qpc_witness_v1 *witness,int tls) {
    uint8_t root[1985];qpc_enrollment_intent_v1 intent=enrollment_intent(path,root);
    qpc_open_options_v1 options={3,0,witness ? (tls ? 2U : 1U) : 0U,witness};
    qpc_error_v1 error;uint64_t handle=0;
    int32_t code=create ? qpc_enrollment_v1_prepare_create((const uint8_t *)path,strlen(path),&intent,&options,&handle,&error) :
        qpc_enrollment_v1_prepare_resume((const uint8_t *)path,strlen(path),&intent,&options,&handle,&error);
    require(code,&error);if(!handle) fail("enrollment pending handle");
    memset(root,0,sizeof(root));memset(&intent,0,sizeof(intent));
    return handle;
}
static uint64_t enrollment_open(const char *path,int create,const qpc_witness_v1 *witness,int tls) {
    uint64_t handle=enrollment_prepare(path,create,witness,tls);qpc_error_v1 error;
    require(qpc_owner_v1_finish_open(handle,&error),&error);return handle;
}
static uint64_t enrollment_parent(const char *path,const qpc_witness_v1 *witness,int tls) {
    uint64_t handle=enrollment_open(path,0,witness,tls);qpc_error_v1 error;
    require(qpc_enrollment_v1_activate(handle,&error),&error);return handle;
}
static qpc_account_pin_v1 enrollment_pin(const char *path,uint8_t root[1985],int renewal) {
    qpc_enrollment_intent_v1 intent=enrollment_intent(path,root);uint8_t version[8];
    qpc_account_pin_v1 pin={.root=root,.root_length=1985};
    memcpy(pin.family,intent.family,32);enrollment_exact(path,"trusted-account",pin.account,32);
    enrollment_exact(path,renewal ? "renewal-version" : "trusted-roster-version",version,8);
    pin.checkpoint.version=enrollment_counter(version);
    enrollment_exact(path,renewal ? "renewal-digest" : "trusted-roster-digest",pin.checkpoint.digest,32);
    return pin;
}
static void enrollment_status(uint64_t handle,qpc_enrollment_status_v1 *status) {
    qpc_error_v1 error;require(qpc_enrollment_v1_status(handle,status,&error),&error);
    if(status->phase<1 || status->phase>6) fail("enrollment status phase");
    uint8_t zero[32]={0};
    if(!memcmp(status->signing_id,zero,32) ||
       ((status->phase<=2) != (!memcmp(status->journal,zero,32)))) fail("enrollment identity shape");
    if(status->phase!=6 && (status->previous.version || status->next.version ||
       memcmp(status->previous.digest,zero,32) || memcmp(status->next.digest,zero,32))) fail("unexpected refresh status");
}
static void credential_status_print(const qpc_credential_renewal_status_v1 *status) {
    uint8_t zero[32]={0};
    if(status->phase>4) fail("unknown credential renewal phase");
    if(status->phase==0 && (memcmp(status->operation,zero,32) || memcmp(status->statement,zero,32)))
        fail("absent renewal has an operation");
    if(status->phase!=0 && (!memcmp(status->operation,zero,32) || !memcmp(status->statement,zero,32)))
        fail("renewal is missing its original identity");
    if(status->phase<2 && (status->checkpoint.version || memcmp(status->checkpoint.digest,zero,32)))
        fail("pending renewal fabricated a checkpoint");
    if(status->phase>=2 && (!status->checkpoint.version || !memcmp(status->checkpoint.digest,zero,32)))
        fail("terminal renewal has no observed checkpoint");
    if((status->phase==3) != (status->observed_at!=0)) fail("renewal observation belongs only to abandonment");
    printf("credential-phase:%u\n",status->phase);encode(status->operation);encode(status->statement);
    printf("credential-head:%llu\n",(unsigned long long)status->checkpoint.version);encode(status->checkpoint.digest);
    printf("credential-observed:%llu\n",(unsigned long long)status->observed_at);
}
static int credential_command(uint64_t handle,const char *path,const char *operation) {
    qpc_error_v1 error;qpc_credential_renewal_status_v1 status;
    if(!strcmp(operation,"enrollment-credential-activate-refused")) {
        int32_t code=qpc_enrollment_v1_activate(handle,&error);record(code,&error);
        if(code!=QPC_VALIDITY) fail("expired target did not refuse activation");
        code=qpc_enrollment_v1_credential_renewal_status(handle,&status,&error);record(code,&error);
        if(code!=QPC_CLOSED) fail("failed expired activation retained owner");
        close_owner(handle);puts("credential-expired-activation-refused");return 0;
    } else if(!strcmp(operation,"enrollment-credential-status")) {
        require(qpc_enrollment_v1_credential_renewal_status(handle,&status,&error),&error);
    } else if(!strcmp(operation,"enrollment-credential-stage") || !strcmp(operation,"enrollment-credential-reject")) {
        uint8_t wire[65536],root[1985],id[32];
        size_t length=enrollment_read(path,"credential-renewal",wire,sizeof(wire));
        enrollment_exact(path,"credential-operation",id,32);
        qpc_account_pin_v1 pin=enrollment_pin(path,root,1);
        int32_t code=qpc_enrollment_v1_stage_credential_renewal(handle,NULL,0,&pin,id,&status,&error);
        record(code,&error);if(code!=QPC_ARGUMENT) fail("empty renewal did not reject before ownership transfer");
        qpc_enrollment_status_v1 retained;enrollment_status(handle,&retained);
        int reject=!strcmp(operation,"enrollment-credential-reject");
        if(reject) wire[length-1]^=1;
        code=qpc_enrollment_v1_stage_credential_renewal(handle,wire,length,&pin,id,&status,&error);record(code,&error);
        if(reject) {
            if(code!=QPC_AUTHENTICATION) fail("invalid renewal signature did not fail authentication");
            code=qpc_enrollment_v1_credential_renewal_status(handle,&status,&error);record(code,&error);
            if(code!=QPC_CLOSED) fail("admitted renewal failure retained original enrollment owner");
            close_owner(handle);puts("credential-signature-refused");return 0;
        }
        require(code,&error);
        qpc_credential_renewal_status_v1 again;
        require(qpc_enrollment_v1_credential_renewal_status(handle,&again,&error),&error);
        if(status.phase!=again.phase || memcmp(status.operation,again.operation,32) ||
           memcmp(status.statement,again.statement,32) || status.checkpoint.version!=again.checkpoint.version ||
           memcmp(status.checkpoint.digest,again.checkpoint.digest,32) || status.observed_at!=again.observed_at)
            fail("renewal stage differs from authenticated readback");
    } else if(!strcmp(operation,"enrollment-credential-reconcile")) {
        uint8_t id[32],statement[32];
        enrollment_exact(path,"credential-operation",id,32);
        enrollment_exact(path,"credential-statement",statement,32);
        require(qpc_enrollment_v1_reconcile_expired_credential_renewal(handle,id,statement,&status,&error),&error);
        uint8_t batch[32];int32_t code=qpc_device_v1_next_account(handle,batch,&error);record(code,&error);
        if(code!=QPC_OWNER_KIND) fail("expiry reconciliation published a device");
    } else fail("unknown credential renewal command");
    credential_status_print(&status);close_owner(handle);
    if(fflush(stdout)) fail("credential status output");
    return 0;
}
struct EnrollmentActivation { uint64_t handle; int32_t code; qpc_error_v1 error; };
static void *enrollment_activation(void *opaque) {
    struct EnrollmentActivation *call=opaque;
    call->code=qpc_enrollment_v1_activate(call->handle,&call->error);return NULL;
}
static int enrollment_command(int argc,char **argv,const qpc_witness_v1 *witness,int tls) {
    if(argc<3) fail("enrollment arguments");
    const char *path=argv[2];qpc_error_v1 error;qpc_enrollment_status_v1 status;
    if(!strcmp(argv[1],"enrollment-key")) {
        require(qpc_enrollment_v1_provision_wrapping_key((const uint8_t *)path,strlen(path),&error),&error);
        puts("enrollment-key");return 0;
    }
    if(!strcmp(argv[1],"enrollment-key-conflict")) {
        int32_t code=qpc_enrollment_v1_provision_wrapping_key((const uint8_t *)path,strlen(path),&error);record(code,&error);
        if(code!=QPC_SCOPE_CONFLICT) fail("active identity permitted wrapping-key recreation");
        puts("enrollment-key-refused:211");return 0;
    }
    if(!strcmp(argv[1],"enrollment-refuse-resume") || !strcmp(argv[1],"enrollment-refuse-create")) {
        int creating=!strcmp(argv[1],"enrollment-refuse-create");
        uint64_t pending=enrollment_prepare(path,creating,witness,tls);
        int32_t code=qpc_owner_v1_finish_open(pending,&error);record(code,&error);
        if(code!=(creating ? QPC_SCOPE_CONFLICT : QPC_DATABASE)) fail("missing registration selected another lineage");
        code=qpc_enrollment_v1_status(pending,&status,&error);record(code,&error);
        if(code!=QPC_CLOSED) fail("failed registration open retained owner");
        close_owner(pending);printf("enrollment-open-refused:%d\n",creating ? QPC_SCOPE_CONFLICT : QPC_DATABASE);return 0;
    }
    int create=!strcmp(argv[1],"enrollment-create");
    uint64_t handle=enrollment_open(path,create,witness,tls);
    enrollment_status(handle,&status);
    if(!strncmp(argv[1],"enrollment-credential-",22)) {
        if(argc!=3) fail("credential renewal arguments");
        return credential_command(handle,path,argv[1]);
    }
    if(create) {
        if(status.phase!=1) fail("new enrollment not Preparing");
    } else if(!strcmp(argv[1],"enrollment-request")) {
        qpc_enrollment_request_v1 first,again;
        require(qpc_enrollment_v1_request(handle,&first,&error),&error);
        require(qpc_enrollment_v1_request(handle,&again,&error),&error);
        if(first.length!=5506 || memcmp(&first,&again,sizeof(first))) fail("original request changed");
        enrollment_write(path,"enrollment-request",first.bytes,first.length);
    } else if(!strcmp(argv[1],"enrollment-request-retry")) {
        qpc_enrollment_request_v1 current;uint8_t original[8192];
        size_t length=enrollment_read(path,"enrollment-request",original,sizeof(original));
        require(qpc_enrollment_v1_request(handle,&current,&error),&error);
        if(current.length!=length || memcmp(current.bytes,original,length)) fail("restart replaced request");
        enrollment_write(path,"enrollment-reopened-request",current.bytes,current.length);
    } else if(!strcmp(argv[1],"enrollment-accept") || !strcmp(argv[1],"enrollment-reject-signature")) {
        uint8_t certificate[8192],roster[8192],root[1985],journal[32];
        size_t cn=enrollment_read(path,"grant-certificate",certificate,sizeof(certificate));
        size_t rn=enrollment_read(path,"grant-roster",roster,sizeof(roster));
        qpc_account_pin_v1 pin=enrollment_pin(path,root,0);
        int32_t code=qpc_enrollment_v1_accept(handle,NULL,0,roster,rn,&pin,journal,&error);
        record(code,&error);if(code!=QPC_ARGUMENT) fail("empty credential admission");
        code=qpc_enrollment_v1_accept(handle,certificate,cn,NULL,0,&pin,journal,&error);
        record(code,&error);if(code!=QPC_ARGUMENT) fail("empty roster admission");
        qpc_enrollment_status_v1 retained;enrollment_status(handle,&retained);
        if(retained.phase!=status.phase || memcmp(retained.signing_id,status.signing_id,32)) fail("shape error consumed enrollment");
        int reject=!strcmp(argv[1],"enrollment-reject-signature");
        if(reject) certificate[cn-1]^=1;
        code=qpc_enrollment_v1_accept(handle,certificate,cn,roster,rn,&pin,journal,&error);record(code,&error);
        if(reject) {
            if(code!=QPC_AUTHENTICATION) fail("bad enrollment signature error");
            code=qpc_enrollment_v1_status(handle,&retained,&error);record(code,&error);
            if(code!=QPC_CLOSED) fail("failed admitted acceptance kept owner");
            close_owner(handle);puts("enrollment-signature-refused");return 0;
        }
        require(code,&error);
    } else if(!strcmp(argv[1],"enrollment-storage")) {
        qpc_setup_preparation_v1 prepared,again;
        require(qpc_enrollment_v1_prepare_storage(handle,&prepared,&error),&error);
        require(qpc_enrollment_v1_prepare_storage(handle,&again,&error),&error);
        if(memcmp(&prepared,&again,sizeof(prepared)) || memcmp(prepared.journal,status.journal,32)) fail("original preparation changed");
        enrollment_write(path,"enrollment-genesis-subject",prepared.subject,96);
        enrollment_write(path,"enrollment-genesis-digest",prepared.image_digest,32);
    } else if(!strcmp(argv[1],"enrollment-refresh")) {
        uint8_t roster[8192],root[1985],original_root[1985];
        size_t rn=enrollment_read(path,"renewal-roster",roster,sizeof(roster));
        qpc_account_pin_v1 old=enrollment_pin(path,original_root,0),next=enrollment_pin(path,root,1);
        int32_t code=qpc_enrollment_v1_refresh_roster(handle,&old.checkpoint,NULL,0,&next,&status,&error);
        record(code,&error);if(code!=QPC_ARGUMENT) fail("empty refresh roster");
        enrollment_status(handle,&status);
        require(qpc_enrollment_v1_refresh_roster(handle,&old.checkpoint,roster,rn,&next,&status,&error),&error);
        if(status.phase!=6 || status.previous.version!=old.checkpoint.version || status.next.version!=next.checkpoint.version)
            fail("refresh did not retain predecessor/target");
    } else if(!strcmp(argv[1],"enrollment-activate-error")) {
        if(argc!=4 || (strcmp(argv[3],"216") && strcmp(argv[3],"218"))) fail("expected enrollment activation error");
        int32_t wanted=!strcmp(argv[3],"216") ? QPC_ANCHOR_REQUIRED : QPC_ANCHOR;
        int32_t code=qpc_enrollment_v1_activate(handle,&error);record(code,&error);
        if(code!=wanted) fail("required witness authority did not refuse activation");
        enrollment_write(path,wanted==QPC_ANCHOR ? "enrollment-authority-refusal" : "enrollment-required-refusal",error.message,error.length);
        code=qpc_enrollment_v1_status(handle,&status,&error);record(code,&error);
        if(code!=QPC_CLOSED) fail("refused activation kept registration owner");
        uint8_t batch[32];code=qpc_device_v1_next_account(handle,batch,&error);record(code,&error);
        if(code!=QPC_CLOSED) fail("refused activation released device owner");
        close_owner(handle);printf("enrollment-activation-refused:%d\n",wanted);return 0;
    } else if(!strcmp(argv[1],"enrollment-cancel-activate")) {
        if(argc!=4 || !witness) fail("enrollment activation cancellation inputs");
        struct EnrollmentActivation call={.handle=handle};pthread_t worker;
        if(pthread_create(&worker,NULL,enrollment_activation,&call)) fail("enrollment activation thread");
        wait_marker(argv[3]);
        int32_t code=qpc_enrollment_v1_status(handle,&status,&error);record(code,&error);
        if(code!=QPC_BUSY) fail("inflight enrollment status not busy");
        code=qpc_enrollment_v1_activate(handle,&error);record(code,&error);
        if(code!=QPC_BUSY) fail("concurrent enrollment activation not busy");
        code=qpc_owner_v1_close(handle,&error);record(code,&error);
        if(code!=QPC_BUSY) fail("inflight registration lease closed");
        require(qpc_owner_v1_cancel(handle,&error),&error);
        if(pthread_join(worker,NULL)) fail("join registration activation");
        record(call.code,&call.error);
        if(call.code!=QPC_ANCHOR) fail("cancelled witness result lost native uncertainty");
        code=qpc_enrollment_v1_status(handle,&status,&error);record(code,&error);
        if(code!=QPC_CLOSED) fail("cancelled activation retained owner");
        close_owner(handle);puts("enrollment-activation-cancelled");return 0;
    } else if(!strcmp(argv[1],"enrollment-activate") || !strcmp(argv[1],"enrollment-hold")) {
        require(qpc_enrollment_v1_activate(handle,&error),&error);
        uint8_t batch[32];require(qpc_device_v1_next_account(handle,batch,&error),&error);
        int32_t code=qpc_enrollment_v1_status(handle,&status,&error);record(code,&error);
        if(code!=QPC_OWNER_KIND) fail("activation retained registration handle kind");
        uint64_t child=0;
        if(!strcmp(argv[1],"enrollment-hold")) {
            if(argc!=4 && argc!=5) fail("enrollment lease barrier");
            if(argc==5) {
                uint64_t sibling=device_peer_open(handle,argv[4],1,NULL);
                child=device_peer_open(handle,argv[4],1,NULL);
                close_owner(sibling);
            }
            enrollment_write(path,"enrollment-held",(const uint8_t *)"1",1);wait_marker(argv[3]);
        }
        close_owner(handle);
        if(child) {
            uint8_t session[32]={1},message[32];
            code=qpc_owner_v1_next_message(child,session,message,&error);record(code,&error);
            if(code!=QPC_CLOSED) fail("closed registration parent retained child authority");
            close_owner(child);
        }
        puts("enrollment-active");encode(batch);return 0;
    } else if(!strcmp(argv[1],"enrollment-cancel")) {
        require(qpc_owner_v1_cancel(handle,&error),&error);
        int32_t code=qpc_enrollment_v1_request(handle,(qpc_enrollment_request_v1[1]){{0}},&error);record(code,&error);
        if(code!=QPC_CANCELLED) fail("registration cancellation");
        close_owner(handle);puts("enrollment-cancelled");return 0;
    } else if(strcmp(argv[1],"enrollment-status")) fail("unknown enrollment command");
    enrollment_status(handle,&status);close_owner(handle);
    printf("enrollment-phase:%u\n",status.phase);encode(status.signing_id);encode(status.journal);return 0;
}
