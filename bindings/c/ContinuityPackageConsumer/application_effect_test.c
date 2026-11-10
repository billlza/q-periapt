/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _GNU_SOURCE 1
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include "application_effect.h"
#ifdef _WIN32
#include "private_record_windows.h"
static int retained_record_control(const char *path) {
    char name[sizeof("application-")+64];
    int width=snprintf(name,sizeof name,"application-02%062u",0u);
    if(width<=0 || (size_t)width>=sizeof name) return -1;
    struct qpc_private_record record;
    if(!qpc_record_open(&record,path,name,1,1)) { (void)qpc_record_close(&record); return -1; }
    if(qpc_record_open(&record,path,name,128,1)) return -1;
    uint8_t bytes[128]; size_t length=record.length;
    int bad=length!=64+sizeof(payload)-1;
    /* A capacity refusal must precede reading; the same handle can still read. */
    if(!bad && !qpc_record_read(&record,bytes,length-1)) bad=1;
    if(!bad && qpc_record_read(&record,bytes,sizeof bytes)) bad=1;
    if(qpc_record_close(&record)) bad=1;
    if(bad) return -1;
    if(qpc_record_retain(path,name,bytes,length,0)
       || !qpc_record_retain(path,"missing-report",bytes,length,0)) return -1;
    bytes[0]^=1;
    if(!qpc_record_retain(path,name,bytes,length,0)
       || !qpc_record_retain(path,name,bytes,length,1)) return -1;
    bytes[0]^=1;
    if(qpc_record_retain(path,name,bytes,length,0)) return -1;
    return 0;
}
#endif

static int record_matches(const char *root, const uint8_t session[32],
                          const uint8_t message[32], const uint8_t *body, size_t length) {
    char name[sizeof("application-")+64];
    memcpy(name,"application-",sizeof("application-")-1);
    for(size_t i=0;i<32;i++) if(snprintf(name+sizeof("application-")-1+i*2,3,"%02x",message[i])!=2) return 0;
#ifdef _WIN32
    HANDLE directory=qpc_file_directory(root);
    if(directory==INVALID_HANDLE_VALUE) return 0;
    WCHAR wide[256];
    int width=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,-1,wide,256);
    if(width<=0) { (void)CloseHandle(directory); return 0; }
    HANDLE file=qpc_file_relative(directory,wide,(size_t)width-1,GENERIC_READ,0,0,NULL);
    int bad=!CloseHandle(directory);
    if(file==INVALID_HANDLE_VALUE) return 0;
    uint8_t data[256]; DWORD count=0;
    if(!ReadFile(file,data,sizeof data,&count,NULL)) bad=1;
    if(!CloseHandle(file)) bad=1;
#else
    int directory=open(root,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(directory<0)return 0;
    int file=openat(directory,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);int bad=close(directory);
    if(file<0)return 0;
    uint8_t data[256];ssize_t count=read(file,data,sizeof(data));
    if(close(file))bad=1;
#endif
    return !bad && length<=sizeof(data)-64 && (size_t)count==64+length
        && !memcmp(data,session,32) && !memcmp(data+32,message,32) && !memcmp(data+64,body,length);
}
static int qpc_consumer_main(int argc,char **argv) {
    if(argc==3 && !strcmp(argv[1],"--reject")) {
        struct Application refused={.path=argv[2],.mode="message"};
        uint8_t session[32]={1},message[32]={2};
        if(!persist_effect(&refused,session,message,payload,sizeof(payload)-1) || refused.created) return 29;
        puts("effect-refusal: original directory and file boundary retained");
        return 0;
    }
    if(argc!=2)return 64;
    struct Application app={.path=argv[1],.mode="message"};
    uint8_t session[32]={1},original[32]={2},fresh[32]={3},wrong[32]={4};
    const uint8_t next[]="continued after pending recovery";
    int initial=persist_effect(&app,session,original,payload,sizeof(payload)-1);
    if(initial) {
#ifdef _WIN32
        fprintf(stderr,"initial effect refused: stage=%d observed_win32_error=%lu\n",initial,(unsigned long)GetLastError());
#else
        fprintf(stderr,"initial effect refused: %d\n",initial);
#endif
        return 20;
    }
    int repeated=persist_effect(&app,session,original,payload,sizeof(payload)-1);
    if(repeated || app.created!=1) {
        fprintf(stderr,"duplicate effect refused: stage=%d created=%u\n",repeated,app.created);
        return 20;
    }
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
#ifdef _WIN32
    if(retained_record_control(argv[1])) return 30;
#endif
    puts("effect-contract: two exact effects, duplicate idempotence, wrong payload and conflicting replay refused");
#ifdef _WIN32
    puts("record-contract: bounded read, exact retention, missing and changed originals refused");
#endif
    return 0;
}
#include "consumer_entry.h"
