/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Included only by the installed root controller workload. */
static void root_authorize_peer(uint64_t registry,const char *public,const char *peer,const uint8_t family[32]) {
    struct material {
        uint8_t root[1985],certificate[8192],roster[8192];
        qpc_account_pin_v1 pin;
        qpc_authority_association_v1 association;
    } *in=calloc(1,sizeof *in);
    if(!in) fail("peer authority input allocation");
    char path[4096];path_join(path,public,"traffic");
    if(fixed(peer,"responder-root",in->root,sizeof in->root) ||
       fixed(peer,"responder-account",in->pin.account,32) ||
       number(peer,"responder-roster-version",&in->pin.checkpoint.version) ||
       fixed(peer,"responder-roster-digest",in->pin.checkpoint.digest,32) ||
       fixed(path,"peer-application",in->association.application,32) ||
       load(peer,"responder-certificate",in->certificate,sizeof in->certificate,&in->association.certificate_length) ||
       load(peer,"responder-roster",in->roster,sizeof in->roster,&in->association.roster_length)) fail("independent peer authority");
    in->pin.root=in->root;in->pin.root_length=sizeof in->root;memcpy(in->pin.family,family,32);
    in->association.struct_size=sizeof in->association;in->association.pin=&in->pin;
    in->association.certificate=in->certificate;in->association.roster=in->roster;
    qpc_authority_checkpoint_v1 checkpoint;qpc_error_v1 error;
    require(qpc_authority_v1_associate(registry,&in->association,&checkpoint,&error),&error);
    if(checkpoint.revision!=1 || memcmp(checkpoint.application,in->association.application,32) ||
       memcmp(checkpoint.account,in->pin.account,32)) fail("peer registry association differs");
    save_number(path,"peer-associated-revision",checkpoint.revision);free(in);
}
static uint8_t traffic_status(uint64_t peer,const uint8_t session[32],const uint8_t message[32]) {
    uint8_t status=255;qpc_error_v1 error;
    require(qpc_owner_v1_message_status(peer,session,message,&status,&error),&error);return status;
}
static void root_traffic(uint64_t device,const char *public,const char *mode,
                         const char *peer_path,const char *address) {
    char path[4096];path_join(path,public,"traffic");
    uint8_t session[32]={0},message[32]={0};uint64_t peer=0;qpc_error_v1 error;
    int connect=!strcmp(mode,"traffic-connect"),reject=!strcmp(mode,"traffic-reject-peer");
    if(!connect && !reject && fixed(path,"session",session,32)) fail("original traffic session");
    int32_t code=(connect || reject) ? qpc_peer_v1_prepare(device,(const uint8_t *)peer_path,strlen(peer_path),1,1,&peer,&error) :
        qpc_peer_v1_prepare_reopen(device,(const uint8_t *)peer_path,strlen(peer_path),1,1,session,&peer,&error);
    require(code,&error);
    if(reject) {
        expect(qpc_owner_v1_finish_open(peer,&error),QPC_DURABLE_ABSENT,&error);
        close_owner(peer);save_number(path,"unknown-peer-code",QPC_DURABLE_ABSENT);return;
    }
    require(qpc_owner_v1_finish_open(peer,&error),&error);
    if(connect) {
        uint8_t request[32];memset(request,155,sizeof request);uint16_t exchanges=0;
        require(qpc_owner_v1_establish(peer,(const uint8_t *)address,strlen(address),request,session,&exchanges,&error),&error);
        if(!exchanges || exchanges>8) fail("root bootstrap exchange bound");
        save(path,"session",session,32);
    } else if(!strcmp(mode,"traffic-receive-cut") || !strcmp(mode,"traffic-receive-recover")) {
        root_receive(peer,path,mode,session);
    } else if(!strcmp(mode,"traffic-rekey")) {
        uint64_t epoch=0;
        require(qpc_owner_v1_rekey(peer,(const uint8_t *)address,strlen(address),session,1,&epoch,&error),&error);
        if(epoch!=1) fail("root traffic rekey epoch");
        save_number(path,"rekey-epoch",epoch);
    } else {
        int unknown=!strcmp(mode,"traffic-send-cut"),retry=!strcmp(mode,"traffic-recover");
        int after=!strcmp(mode,"traffic-after-rekey");
        if(!unknown && !retry && !after) fail("root traffic mode");
        if(retry) {
            if(fixed(path,"message-before",message,32) || traffic_status(peer,session,message)!=QPC_MESSAGE_COMMITTED)
                fail("restart lost original committed message");
        } else {
            require(qpc_owner_v1_next_message(peer,session,message,&error),&error);
            if(counter(message)!=(after ? 1U : 0U) || counter(message+8)!=0)
                fail("root traffic original epoch or sequence");
            save(path,after ? "message-after" : "message-before",message,32);
        }
        const uint8_t ad[]="owned-service";
        uint8_t consumption=99;uint16_t exchanges=99;
        code=qpc_owner_v1_send(peer,(const uint8_t *)address,strlen(address),session,message,
                              payload,sizeof payload-1,ad,sizeof ad-1,&consumption,&exchanges,&error);
        if(unknown) {
            /* These are the transport's documented uncertain outcomes. The
             * driver independently proves the receiver exited after persistence. */
            if(code!=QPC_NETWORK && code!=QPC_RETRY_EXHAUSTED && code!=QPC_DEADLINE && code!=QPC_TLS)
                fail("receiver loss was not reported as transport uncertainty");
            expect(code,code,&error);
            if(consumption || exchanges || traffic_status(peer,session,message)!=QPC_MESSAGE_COMMITTED)
                fail("receiver loss falsely acknowledged or discarded the original message");
            save_number(path,"uncertain-code",(uint64_t)code);
            pause_for_kill(path,"sender");
        }
        require(code,&error);
        if(consumption!=QPC_CONSUMPTION_CONFIRMED || !exchanges || exchanges>8 ||
           traffic_status(peer,session,message)!=QPC_MESSAGE_ACKNOWLEDGED) fail("root traffic consumption absent");
        save_number(path,retry ? "recovered-status" : "after-status",QPC_MESSAGE_ACKNOWLEDGED);
    }
    close_owner(peer);
}
