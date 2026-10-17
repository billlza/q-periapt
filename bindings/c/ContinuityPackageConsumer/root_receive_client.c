/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "application_effect.h"
struct RootReceiver {
    struct Application application;
    const char *public;
    uint8_t session[32];
    int cut;
};
static int32_t root_receive_effect(void *opaque,const uint8_t session[32],const uint8_t message[32],
                                   const uint8_t *plaintext,size_t length) {
    struct RootReceiver *receiver=opaque;struct Application *app=&receiver->application;
    app->calls++;
    if(memcmp(session,receiver->session,32)) return 41;
    qpc_error_v1 error;
    expect(qpc_owner_v1_close(app->handle,&error),QPC_BUSY,&error);
    if(persist_effect(app,session,message,plaintext,length)) return 31;
    if(receiver->cut) pause_for_kill(receiver->public,"receiver");
    return 0;
}
static void root_receive(uint64_t peer,const char *public,const char *mode,const uint8_t session[32]) {
    struct RootReceiver receiver={.application={.handle=peer,.path=public},.public=public,
                                  .cut=!strcmp(mode,"traffic-receive-cut")};
    memcpy(receiver.session,session,32);
    uint16_t port=0;qpc_error_v1 error;const uint8_t bind[]="127.0.0.1:0";
    require(qpc_owner_v1_listen(peer,bind,sizeof bind-1,&port,&error),&error);
    if(!port || printf("root-listening:%u\n",(unsigned)port)<0 || fflush(stdout)) fail("root receive readiness");
    qpc_served_v1 served;
    require(qpc_owner_v1_serve(peer,root_receive_effect,&receiver,&served,&error),&error);
    if(receiver.cut || served.kind!=2 || served.duplicate || receiver.application.calls!=1 ||
       receiver.application.created || memcmp(served.session,session,32)) fail("root receive recovery outcome");
    save(public,"reply-received",served.message,32);
    save_number(public,"reply-created-on-recovery",receiver.application.created);
}
