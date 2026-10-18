/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Root reports retain the same 8 MiB caller bound on every supported host. */
#include <stdio.h>
#include "private_record_windows.h"

static int run(const char *path) {
    const size_t maximum=8388608;
    unsigned char *bytes=malloc(maximum+1),*observed=malloc(maximum);
    if(!bytes || !observed) { free(bytes); free(observed); return 10; }
    for(size_t i=0;i<=maximum;++i) bytes[i]=(unsigned char)(i^(i>>8));
    int created=99;
    if(!qpc_file_commit(path,"default-too-large",bytes,1048577,&created) || created) return 11;
    if(!qpc_file_commit_bounded(path,"root-too-large",bytes,maximum+1,maximum,&created) || created) return 12;
    if(!qpc_file_commit_bounded(path,"invalid-limit",bytes,1,maximum+1,&created) || created) return 13;
    if(!qpc_file_commit_bounded(path,"empty-report",bytes,0,maximum,&created) || created) return 14;
    if(qpc_file_commit_bounded(path,"root-report",bytes,maximum,maximum,&created) || created!=1) return 15;
    if(qpc_file_commit_bounded(path,"root-report",bytes,maximum,maximum,&created) || created) return 16;
    /* A difference at the final byte must never overwrite the original. */
    bytes[maximum-1]^=1;
    if(!qpc_file_commit_bounded(path,"root-report",bytes,maximum,maximum,&created) || created) return 17;
    bytes[maximum-1]^=1;
    struct qpc_private_record record;
    if(qpc_record_open(&record,path,"root-report",maximum,0) || record.length!=maximum
       || qpc_record_read(&record,observed,maximum) || qpc_record_close(&record)
       || memcmp(bytes,observed,maximum)) return 18;
    HANDLE directory=qpc_file_directory(path);
    if(directory==INVALID_HANDLE_VALUE) return 19;
    WCHAR missing[][32]={L"default-too-large",L"root-too-large",L"invalid-limit",L"empty-report"};
    for(size_t i=0;i<sizeof missing/sizeof *missing;++i)
        if(qpc_file_existing(directory,missing[i],bytes,1)!=1) return 20;
    WCHAR name[]=L"root-report";
    HANDLE file=qpc_file_relative(directory,name,wcslen(name),DELETE,0,0,NULL);
    FILE_DISPOSITION_INFO disposition={TRUE};
    if(file==INVALID_HANDLE_VALUE || !SetFileInformationByHandle(file,FileDispositionInfo,&disposition,sizeof disposition)
       || !CloseHandle(file) || !FlushFileBuffers(directory) || !CloseHandle(directory)) return 21;
    free(bytes); free(observed);
    puts("WINDOWS_ROOT_PUBLICATION_PASS maximum=8388608 default_limit=1048576 exact_duplicate_retained=true conflict_preserves_original=true bounds_before_publication=true full_readback=true");
    return 0;
}
static int qpc_consumer_main(int argc,char **argv) {
    if(argc!=2) return 64;
    int result=run(argv[1]);
    if(result) fprintf(stderr,"root publication control failed: stage=%d error=%lu\n",result,(unsigned long)GetLastError());
    return result;
}
#include "consumer_entry.h"
