/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Qualification driver; independently issued public control-plane inputs only. */
struct PeerRosterCall {
    uint64_t parent;
    const uint8_t *wire;
    size_t length;
    const qpc_account_pin_v1 *pin;
    qpc_roster_checkpoint_v1 result;
    qpc_error_v1 error;
    int32_t code;
};
static void *peer_roster_call(void *opaque) {
    struct PeerRosterCall *call=opaque;
    call->code=qpc_device_v1_admit_peer_roster(call->parent,call->wire,call->length,
        call->pin,&call->result,&call->error);
    return NULL;
}
static int peer_roster_command(int argc,char **argv,uint64_t parent) {
    if((argc!=5 && argc!=6 && argc!=11) || !parent) fail("peer roster command requires original parent and target");
    const char *path=argv[3],*mode=argv[4];uint8_t root[1985],wire[65536],version[8];
    enrollment_exact(path,"root",root,sizeof(root));
    qpc_account_pin_v1 pin={.root=root,.root_length=sizeof(root)};
    enrollment_exact(path,"account",pin.account,32);enrollment_exact(path,"family",pin.family,32);
    enrollment_exact(path,"version",version,8);pin.checkpoint.version=enrollment_counter(version);
    enrollment_exact(path,"digest",pin.checkpoint.digest,32);
    size_t length=enrollment_read(path,"roster",wire,sizeof(wire));
    qpc_roster_checkpoint_v1 result,untouched;qpc_error_v1 error;
    int suspend=!strcmp(mode,"suspend");
    struct AccountSend send={.parent=parent,.count=2,.selected=1,.body=payload,.body_length=sizeof(payload)-1,.address="127.0.0.1:1"};
    if(suspend) {
        if(argc!=11) fail("complete original batch inputs");
        decode(argv[6],send.targets[0].session);decode(argv[8],send.targets[1].session);
        decode(argv[9],send.account);decode(argv[10],send.id);
        send.targets[0].peer=device_peer_open(parent,argv[5],1,send.targets[0].session);
        send.targets[1].peer=device_peer_open(parent,argv[7],1,send.targets[1].session);
    }
    memset(&result,0xa5,sizeof(result));untouched=result;
    credential_expect(qpc_device_v1_admit_peer_roster(parent,NULL,0,&pin,&result,&error),QPC_ARGUMENT,&error);
    pin.checkpoint.digest[0]^=1;
    credential_expect(qpc_device_v1_admit_peer_roster(parent,wire,length,&pin,&result,&error),QPC_CHECKPOINT,&error);
    pin.checkpoint.digest[0]^=1;
    if(memcmp(&result,&untouched,sizeof(result))) fail("failed roster admission changed output");
    if(!strcmp(mode,"validate")) {
        if(argc!=5) fail("peer roster validation arguments");
        close_owner(parent);puts("peer-roster-inputs-refused");return 0;
    }
    if(!strcmp(mode,"lost") || !strcmp(mode,"cancel-active")) {
        int cancelling=!strcmp(mode,"cancel-active");
        if(argc!=(cancelling ? 6 : 5)) fail("peer roster interruption arguments");
        struct PeerRosterCall call={.parent=parent,.wire=wire,.length=length,.pin=&pin,.result=result};
        if(cancelling) {
            pthread_t worker;if(pthread_create(&worker,NULL,peer_roster_call,&call)) fail("roster worker create");
            wait_marker(argv[5]);
            credential_expect(qpc_owner_v1_close(parent,&error),QPC_BUSY,&error);
            struct timespec before,after;if(clock_gettime(CLOCK_MONOTONIC,&before)) fail("roster cancel clock");
            require(qpc_owner_v1_cancel(parent,&error),&error);
            if(pthread_join(worker,NULL)) fail("roster worker join");
            if(clock_gettime(CLOCK_MONOTONIC,&after)) fail("roster cancel clock");
            int64_t ns=(int64_t)(after.tv_sec-before.tv_sec)*1000000000LL+after.tv_nsec-before.tv_nsec;
            if(ns<0 || ns>=1000000000LL) fail("roster cancellation exceeded observation bound");
        } else peer_roster_call(&call);
        credential_expect(call.code,QPC_ANCHOR,&call.error);
        if(memcmp(&call.result,&untouched,sizeof(untouched))) fail("unknown roster commit published checkpoint");
        uint8_t next[32],zero[32]={0};memset(next,0xa5,sizeof(next));
        credential_expect(qpc_device_v1_next_account(parent,next,&error),cancelling ? QPC_CANCELLED : QPC_DURABLE_CLOSED,&error);
        if(memcmp(next,zero,sizeof(next))) fail("unavailable roster owner published next account ID");
        puts(cancelling ? "peer-roster-cancelled-after-advance" : "peer-roster-outcome-unavailable");
    } else if(!strcmp(mode,"cancel")) {
        require(qpc_owner_v1_cancel(parent,&error),&error);
        credential_expect(qpc_device_v1_admit_peer_roster(parent,wire,length,&pin,&result,&error),QPC_CANCELLED,&error);
        if(memcmp(&result,&untouched,sizeof(result))) fail("cancelled roster returned checkpoint");
        puts("peer-roster-cancelled");
    } else if(!strcmp(mode,"admit") || suspend) {
        require(qpc_device_v1_admit_peer_roster(parent,wire,length,&pin,&result,&error),&error);
        if(result.version!=pin.checkpoint.version || memcmp(result.digest,pin.checkpoint.digest,32)) fail("current peer roster differs");
        qpc_roster_checkpoint_v1 replay;
        require(qpc_device_v1_admit_peer_roster(parent,wire,length,&pin,&replay,&error),&error);
        if(result.version!=replay.version || memcmp(result.digest,replay.digest,32)) fail("exact peer roster retry differs");
        if(suspend) {
            account_call(&send);account_failed(&send,QPC_SCOPE,"revoked-original-member");
            close_owner(send.targets[1].peer);close_owner(send.targets[0].peer);
        }
        puts("peer-roster-admitted");
    } else fail("unknown peer roster mode");
    close_owner(parent);return 0;
}
