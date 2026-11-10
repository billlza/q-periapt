#define _GNU_SOURCE
#include "q_periapt.h"
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
 if(argc!=3)return 2;
 long pagesize=sysconf(_SC_PAGESIZE);if(pagesize<4096)return 3;
 size_t n=(size_t)pagesize;
 unsigned char *p=mmap(NULL,n*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(p==MAP_FAILED)return 4;
 if(mprotect(p+n,n,PROT_NONE)!=0)return 5;
 /* Both prefixes are aligned; the next options field lies in PROT_NONE. */
 uint32_t *h=(uint32_t *)(p+n-8);h[0]=4;h[1]=0;
 int revision=strcmp(argv[2],"revision")==0;
 uint64_t out=UINT64_MAX;int32_t status;
 if(strcmp(argv[1],"runtime")==0){if(revision)h[0]=sizeof(QPeriaptRuntimeOptions);status=q_periapt_sdk_runtime_new((const QPeriaptRuntimeOptions *)h,&out);}
 else if(strcmp(argv[1],"provision")==0){if(revision)h[0]=sizeof(QPeriaptStoreOptions);status=q_periapt_sdk_runtime_provision_store((const QPeriaptStoreOptions *)h,&out);}
 else if(strcmp(argv[1],"open")==0){if(revision)h[0]=sizeof(QPeriaptStoreOptions);status=q_periapt_sdk_runtime_open_store((const QPeriaptStoreOptions *)h,&out);}
 else if(strcmp(argv[1],"client")==0){if(revision)h[0]=sizeof(QPeriaptConnectionOptions);status=q_periapt_sdk_connection_client_new(0,(const QPeriaptConnectionOptions *)h,&out);}
 else if(strcmp(argv[1],"server")==0){if(revision)h[0]=sizeof(QPeriaptConnectionOptions);status=q_periapt_sdk_connection_server_new(0,(const QPeriaptConnectionOptions *)h,&out);}
 else return 6;
 printf("status=%d; output_untouched=%d\n",status,out==UINT64_MAX);
 if(munmap(p,n*2)!=0)return 7;
 return status==Q_PERIAPT_ERR_LIMITS && out==UINT64_MAX ? 0:8;
}
