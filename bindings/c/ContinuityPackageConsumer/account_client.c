/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Included by the qualification CLI so all account calls use the real C ABI. */
_Static_assert(sizeof(qpc_account_target_v1) == 40, "account target ABI");
_Static_assert(sizeof(qpc_account_delivered_v1) == 88, "account delivery ABI");
_Static_assert(offsetof(qpc_account_delivered_v1, outcome) == 80, "account outcome ABI");
struct AccountSend {
    uint64_t parent;
    qpc_account_target_v1 targets[2];
    size_t count, selected;
    uint8_t id[32], account[32];
    const char *address;
    const uint8_t *body;
    size_t body_length;
    qpc_account_delivered_v1 result;
    qpc_error_v1 error;
    int32_t code;
};
static void *account_call(void *opaque) {
    struct AccountSend *s=opaque;
    memset(&s->result, 0xff, sizeof(s->result));
    s->code=qpc_device_v1_send_account_member(s->parent,s->targets,s->count,s->selected,
        s->id,s->account,(const uint8_t *)s->address,strlen(s->address),
        s->body,s->body_length,ad,sizeof(ad)-1,&s->result,&s->error);
    return NULL;
}
static void account_failed(const struct AccountSend *s, int32_t expected, const char *mode) {
    record(s->code,&s->error);
    const qpc_account_delivered_v1 empty={0};
    int output_zero = memcmp(&s->result,&empty,sizeof(empty)) == 0;
    if (s->code!=expected || !output_zero) {
        fprintf(stderr,"account-refusal mode=%s expected=%ld actual=%ld output_zero=%d\n",
            mode,(long)expected,(long)s->code,output_zero);
        fail("account refusal or output initialization differs");
    }
    printf("account-refused:%d\n",s->code);
}
static void account_shape_check(void) {
    qpc_account_target_v1 values[33]={{0}};
    const uint8_t id[32]={1};qpc_error_v1 error;qpc_account_delivered_v1 result;
    const qpc_account_delivered_v1 empty={0};
    const size_t counts[4]={0,33,2,32}, selected[4]={0,0,2,0};
    for(size_t i=0;i<4;++i){
        memset(&result,0xff,sizeof(result));
        int32_t code=qpc_device_v1_send_account_member(0,values,counts[i],selected[i],id,id,
            (const uint8_t *)"127.0.0.1:1",11,NULL,0,NULL,0,&result,&error);
        record(code,&error);
        if(code!=QPC_ARGUMENT || memcmp(&result,&empty,sizeof(empty)))fail("account array shape admitted");
    }
}
static int account_command(int argc, char **argv,const qpc_witness_v1 *witness,int witness_tls) {
    if (argc<3) fail("account local path missing");
    account_shape_check();
    uint64_t parent=device_open(argv[2],witness,witness_tls);
    qpc_error_v1 error;
    if (!strcmp(argv[1],"account-next")) {
        if(argc!=3) fail("account next arguments");
        uint8_t id[32];require(qpc_device_v1_next_account(parent,id,&error),&error);encode(id);
    } else if (!strcmp(argv[1],"account-status")) {
        if(argc!=4) fail("account status arguments");
        uint8_t id[32],report[32],value=255;decode(argv[3],id);
        require(qpc_device_v1_account_status(parent,id,&value,report,&error),&error);
        printf("account-status:%u\n",value);encode(report);
    } else if (!strcmp(argv[1],"account-connect")) {
        if(argc!=9) fail("account connect arguments");
        uint64_t peers[2]={device_peer_open(parent,argv[3],1,NULL),device_peer_open(parent,argv[4],1,NULL)};
        for(size_t i=0;i<2;++i){
            uint8_t request[32],session[32];uint16_t exchanges=0;decode(argv[7+i],request);
            require(qpc_owner_v1_establish(peers[i],(const uint8_t *)argv[5+i],strlen(argv[5+i]),
                request,session,&exchanges,&error),&error);encode(session);
        }
        close_owner(peers[1]);close_owner(peers[0]);
    } else if (!strcmp(argv[1],"account-send")) {
        if(argc!=12 && argc!=13) fail("account send arguments");
        struct AccountSend s={.parent=parent,.count=2,.body=payload,.body_length=sizeof(payload)-1,.address=argv[10]};
        if(strcmp(argv[9],"0") && strcmp(argv[9],"1")) fail("account selected index");
        s.selected=!strcmp(argv[9],"1");
        decode(argv[4],s.targets[0].session);decode(argv[6],s.targets[1].session);
        decode(argv[7],s.account);decode(argv[8],s.id);
        uint64_t peers[2]={device_peer_open(parent,argv[3],1,s.targets[0].session),device_peer_open(parent,argv[5],1,s.targets[1].session)};
        s.targets[0].peer=peers[0];s.targets[1].peer=peers[1];
        const char *mode=argv[11];int32_t expected=0;uint64_t other_parent=0,other_peer=0;
        if(!strcmp(mode,"unary")){
            if(argc!=13)fail("original member ID missing");
            uint8_t message[32],consumption=255;uint16_t exchanges=255;decode(argv[12],message);
            int32_t code=qpc_owner_v1_send(peers[s.selected],(const uint8_t *)s.address,strlen(s.address),
                s.targets[s.selected].session,message,payload,sizeof(payload)-1,ad,sizeof(ad)-1,&consumption,&exchanges,&error);
            record(code,&error);
            if(code!=QPC_SUSPENDED || consumption || exchanges)fail("unary carrier released aggregate member");
            puts("account-refused:215");close_owner(peers[1]);close_owner(peers[0]);close_owner(parent);return 0;
        }
        if(!strcmp(mode,"reverse-retained")){
            qpc_account_target_v1 temporary=s.targets[0];s.targets[0]=s.targets[1];s.targets[1]=temporary;
            s.selected=1-s.selected;
        }
        if(!strcmp(mode,"omit")){s.count=1;s.selected=0;expected=QPC_POLICY_DENIED;}
        else if(!strcmp(mode,"duplicate-peer")){s.targets[1].peer=peers[0];expected=QPC_ARGUMENT;}
        else if(!strcmp(mode,"duplicate-session")){memcpy(s.targets[1].session,s.targets[0].session,32);expected=QPC_ARGUMENT;}
        else if(!strcmp(mode,"cancel-peer")){require(qpc_owner_v1_cancel(peers[1],&error),&error);expected=QPC_CANCELLED;}
        else if(!strcmp(mode,"closed-peer")){close_owner(peers[1]);peers[1]=0;expected=QPC_CLOSED;}
        else if(!strcmp(mode,"wrong-parent")){
            if(argc!=13)fail("other original device missing");
            other_parent=device_open(argv[12],witness,witness_tls);
            other_peer=device_peer_open(other_parent,argv[12],2,s.targets[1].session);
            s.targets[1].peer=other_peer;expected=QPC_SCOPE_CONFLICT;
        }else if(!strcmp(mode,"changed-input")){s.body=(const uint8_t *)"different";s.body_length=9;expected=QPC_SCOPE_CONFLICT;}
        else if(!strcmp(mode,"unknown")){expected=QPC_RETRY_EXHAUSTED;}
        else if(!strcmp(mode,"cancel-active")){
            if(argc!=13)fail("account socket barrier missing");
            uint64_t idle=device_peer_open(parent,argv[3],1,s.targets[0].session);
            pthread_t worker;if(pthread_create(&worker,NULL,account_call,&s))fail("account thread create");
            wait_marker(argv[12]);
            close_owner(idle);
            uint64_t busy[3]={parent,peers[0],peers[1]};
            for(size_t i=0;i<3;++i){int32_t code=qpc_owner_v1_close(busy[i],&error);record(code,&error);if(code!=QPC_BUSY)fail("aggregate owner closed during call");}
            struct timespec before,after;if(clock_gettime(CLOCK_MONOTONIC,&before))fail("account clock");
            require(qpc_owner_v1_cancel(peers[1],&error),&error);
            if(pthread_join(worker,NULL))fail("account thread join");
            if(clock_gettime(CLOCK_MONOTONIC,&after))fail("account clock");
            int64_t ns=(int64_t)(after.tv_sec-before.tv_sec)*1000000000LL+after.tv_nsec-before.tv_nsec;
            if(ns<0 || ns>=1000000000LL)fail("account cancellation exceeded observation bound");
            account_failed(&s,QPC_CANCELLED,mode);
            uint8_t next[32];require(qpc_device_v1_next_account(parent,next,&error),&error);
            require(qpc_owner_v1_next_message(peers[0],s.targets[0].session,next,&error),&error);
            printf("account-cancel-active:%lld:3\n",(long long)(ns/1000000LL));
            close_owner(peers[1]);close_owner(peers[0]);close_owner(parent);return 0;
        }else if(strcmp(mode,"deliver") && strcmp(mode,"retained") && strcmp(mode,"reverse-retained"))fail("account mode");
        account_call(&s);
        if(expected)account_failed(&s,expected,mode);
        else{
            require(s.code,&s.error);
            if(s.result.outcome!=QPC_ACCOUNT_CONFIRMED || memcmp(s.result.session,s.targets[s.selected].session,32))fail("account delivery scope/outcome");
            if((!strcmp(mode,"retained") || !strcmp(mode,"reverse-retained")) != (s.result.exchanges==0))fail("retained account network count");
            printf("account-delivered:%u:%u\n",s.result.outcome,s.result.exchanges);
            encode(s.result.session);encode(s.result.message);
            for (size_t i = 0; i < 16; ++i) {
                printf("%02x", s.result.device[i]);
            }
            putchar('\n');
        }
        if (other_peer) { close_owner(other_peer); }
        if (other_parent) { close_owner(other_parent); }
        if (peers[1]) { close_owner(peers[1]); }
        close_owner(peers[0]);
    }else fail("unknown account command");
    close_owner(parent);return 0;
}
