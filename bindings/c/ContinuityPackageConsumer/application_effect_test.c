/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _GNU_SOURCE 1
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "application_effect.h"

static int record_matches(const char *root, const uint8_t session[32],
                          const uint8_t message[32], const uint8_t *body, size_t length) {
    char name[sizeof("application-")+64];
    memcpy(name,"application-",sizeof("application-")-1);
    for(size_t i=0;i<32;i++) if(snprintf(name+sizeof("application-")-1+i*2,3,"%02x",message[i])!=2) return 0;
    int directory=open(root,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(directory<0)return 0;
    int file=openat(directory,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);int bad=close(directory);
    if(file<0)return 0;
    uint8_t data[256];ssize_t count=read(file,data,sizeof(data));
    if(close(file))bad=1;
    return !bad && length<=sizeof(data)-64 && count==(ssize_t)(64+length)
        && !memcmp(data,session,32) && !memcmp(data+32,message,32) && !memcmp(data+64,body,length);
}
int main(int argc,char **argv) {
    if(argc!=2)return 64;
    struct Application app={.path=argv[1],.mode="message"};
    uint8_t session[32]={1},original[32]={2},fresh[32]={3},wrong[32]={4};
    const uint8_t next[]="continued after pending recovery";
    if(persist_effect(&app,session,original,payload,sizeof(payload)-1)
        ||persist_effect(&app,session,original,payload,sizeof(payload)-1)||app.created!=1)return 20;
    app.mode="fresh-message";
    int result=persist_effect(&app,session,fresh,next,sizeof(next)-1);
    if(result){fprintf(stderr,"fresh effect refused: %d\n",result);return 23;}
    if(persist_effect(&app,session,fresh,next,sizeof(next)-1)||app.created!=2)return 24;
    if(!persist_effect(&app,session,original,next,sizeof(next)-1))return 25;
    if(!persist_effect(&app,session,wrong,payload,sizeof(payload)-1))return 26;
    app.mode="message";
    if(!persist_effect(&app,session,wrong,next,sizeof(next)-1)||app.created!=2)return 27;
    if(!record_matches(argv[1],session,original,payload,sizeof(payload)-1)
        ||!record_matches(argv[1],session,fresh,next,sizeof(next)-1))return 28;
    puts("effect-contract: two exact effects, duplicate idempotence, wrong payload and conflicting replay refused");
    return 0;
}
