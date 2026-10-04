/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Included by the C qualification client after the registration input helpers. */
static void credential_expect(int32_t code,int32_t expected,const qpc_error_v1 *error) {
    record(code,error);
    if(code!=expected) {
        fprintf(stderr,"credential peer status=%d expected=%d\n",code,expected);
        fail("credential peer boundary differed");
    }
}
static void credential_peer_refused(uint64_t parent,const char *path,uint32_t role,
                                    const uint8_t *session,int32_t expected) {
    uint64_t child=0;qpc_error_v1 error;
    int32_t code=session ? qpc_peer_v1_prepare_reopen(parent,(const uint8_t *)path,strlen(path),1,role,session,&child,&error) :
        qpc_peer_v1_prepare(parent,(const uint8_t *)path,strlen(path),1,role,&child,&error);
    require(code,&error);
    credential_expect(qpc_owner_v1_finish_open(child,&error),expected,&error);
    credential_expect(qpc_owner_v1_finish_open(child,&error),QPC_CLOSED,&error);
    close_owner(child);
}
static void credential_peer_admit(uint64_t parent,const char *path,int controls) {
    uint8_t wire[65536],root[1985],operation[32];
    size_t length=enrollment_read(path,"credential-renewal",wire,sizeof(wire));
    enrollment_exact(path,"credential-operation",operation,32);
    qpc_account_pin_v1 pin=enrollment_pin(path,root,1);
    qpc_roster_checkpoint_v1 result,untouched;qpc_error_v1 error;
    memset(&result,0xa5,sizeof(result));untouched=result;
    if(controls) {
        credential_expect(qpc_device_v1_admit_peer_credential_renewal(parent,NULL,0,&pin,operation,&result,&error),QPC_ARGUMENT,&error);
        pin.checkpoint.digest[0]^=1;
        credential_expect(qpc_device_v1_admit_peer_credential_renewal(parent,wire,length,&pin,operation,&result,&error),QPC_CHECKPOINT,&error);
        pin.checkpoint.digest[0]^=1;operation[0]^=1;
        credential_expect(qpc_device_v1_admit_peer_credential_renewal(parent,wire,length,&pin,operation,&result,&error),QPC_SCOPE_CONFLICT,&error);
        operation[0]^=1;
        if(memcmp(&result,&untouched,sizeof(result))) fail("failed peer grant wrote a successful checkpoint");
    }
    require(qpc_device_v1_admit_peer_credential_renewal(parent,wire,length,&pin,operation,&result,&error),&error);
    if(result.version!=pin.checkpoint.version || memcmp(result.digest,pin.checkpoint.digest,32))
        fail("peer grant did not return independently expected checkpoint");
    qpc_roster_checkpoint_v1 replay;
    require(qpc_device_v1_admit_peer_credential_renewal(parent,wire,length,&pin,operation,&replay,&error),&error);
    if(result.version!=replay.version || memcmp(result.digest,replay.digest,32)) fail("peer grant retry changed checkpoint");
}
static int credential_peer_check(int argc,char **argv) {
    if(argc!=7) fail("credential peer arguments");
    const char *local=argv[2];uint8_t session[32],message[32],next[32],wrong[32];
    decode(argv[5],session);decode(argv[6],message);memcpy(wrong,session,32);wrong[0]^=1;
    uint64_t parent=device_open(local,NULL,0);qpc_error_v1 error;
    credential_peer_refused(parent,local,2,session,QPC_VALIDITY);
    credential_peer_admit(parent,argv[3],1);
    credential_peer_refused(parent,local,2,NULL,QPC_VALIDITY);
    credential_peer_refused(parent,local,1,session,QPC_SCOPE_CONFLICT);
    credential_peer_refused(parent,local,2,wrong,QPC_DURABLE_ABSENT);
    uint64_t first=device_peer_open(parent,local,2,session);
    if(status(first,session,message)!=QPC_MESSAGE_COMMITTED) fail("first grant lost original outbox");
    require(qpc_owner_v1_next_message(first,session,next,&error),&error);
    uint8_t original_next[32];memcpy(original_next,next,32);
    credential_peer_admit(parent,argv[4],0);
    uint8_t zero[32]={0};memset(next,0xa5,32);
    credential_expect(qpc_owner_v1_next_message(first,session,next,&error),QPC_SCOPE_CONFLICT,&error);
    if(memcmp(next,zero,32)) fail("stale grant returned nonzero message output");
    close_owner(first);
    uint64_t current=device_peer_open(parent,local,2,session);
    if(status(current,session,message)!=QPC_MESSAGE_COMMITTED) fail("second grant lost original outbox");
    require(qpc_owner_v1_next_message(current,session,next,&error),&error);
    if(memcmp(next,original_next,32)) fail("refused stale child advanced the next message slot");
    close_owner(current);close_owner(parent);
    parent=device_open(local,NULL,0);current=device_peer_open(parent,local,2,session);
    if(status(current,session,message)!=QPC_MESSAGE_COMMITTED) fail("restart lost renewed peer or original outbox");
    close_owner(current);close_owner(parent);
    puts("credential-peer-passed");if(fflush(stdout)) fail("credential peer output");return 0;
}
