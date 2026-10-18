/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Distinguish extended-path spelling from publication-handle sharing. */
#include "consumer_marker.h"
#include "private_files_windows.h"

static int exact_input(const char *path,int raw) {
    FILE *file=NULL;
    if(raw) {
        WCHAR wide[32768];
        if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,wide,32768)) return -1;
        if(_wfopen_s(&file,wide,L"rb")) return -1;
    } else file=qpc_input_file(path);
    if(!file) return -1;
    int byte=fgetc(file),end=fgetc(file),bad=ferror(file),closed=fclose(file);
    return byte=='1' && end==EOF && !bad && !closed ? 0 : -1;
}

static int run(const char *path) {
    const char name[]="input-\xe4\xb8\xad\xe6\x96\x87";
    WCHAR leaf[]=L"input-\u4e2d\u6587";
    int created=0;
    if(qpc_file_commit(path,name,(const uint8_t *)"1",1,&created) || !created) return 10;
    HANDLE directory=qpc_file_directory(path);
    if(directory==INVALID_HANDLE_VALUE) return 11;
    WCHAR wide[8192];char canonical[32768],ordinary[32768],extended[32768];
    DWORD count=GetFinalPathNameByHandleW(directory,wide,8192,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if(!count || count>=8192 || !WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,-1,
                                                   canonical,(int)sizeof canonical,NULL,NULL)) return 12;
    int a=snprintf(ordinary,sizeof ordinary,"%s/%s",path,name);
    int b=snprintf(extended,sizeof extended,"%s/%s",canonical,name);
    if(a<=0 || (size_t)a>=sizeof ordinary || b<=0 || (size_t)b>=sizeof extended) return 13;
    SetLastError(ERROR_SUCCESS);
    int original=exact_input(extended,1);DWORD path_error=GetLastError();
    printf("WINDOWS_INPUT_RAW_EXTENDED success=%d error=%lu\n",original==0,(unsigned long)path_error);
    if(original==0 || exact_input(ordinary,0) || exact_input(extended,0)) return 14;
    if(qpc_marker_read(ordinary)!=1 || qpc_marker_read(extended)!=1) return 15;
    HANDLE publisher=qpc_file_relative(directory,leaf,wcslen(leaf),GENERIC_READ|GENERIC_WRITE|DELETE,0,0,NULL);
    if(publisher==INVALID_HANDLE_VALUE) return 16;
    SetLastError(ERROR_SUCCESS);
    original=exact_input(ordinary,0);DWORD sharing=GetLastError();
    printf("WINDOWS_INPUT_OLD_MARKER success=%d error=%lu\n",original==0,(unsigned long)sharing);
    if(original==0 || sharing!=ERROR_SHARING_VIOLATION
       || qpc_marker_read(ordinary)!=1 || qpc_marker_read(extended)!=1) return 17;
    OVERLAPPED position={0};
    if(!LockFileEx(publisher,LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,
                  0,MAXDWORD,MAXDWORD,&position)) return 18;
    if(qpc_marker_read(ordinary)!=-1 || GetLastError()!=ERROR_LOCK_VIOLATION) return 19;
    if(!UnlockFileEx(publisher,0,MAXDWORD,MAXDWORD,&position) || !CloseHandle(publisher)) return 20;
    if(qpc_marker_read(ordinary)!=1) return 21;
    char invalid[32768];
    const char *names[]={"absent-marker","wrong-marker","long-marker"};
    for(size_t i=0;i<3;++i) {
        if(i && (qpc_file_commit(path,names[i],(const uint8_t *)(i==1 ? "0" : "11"),i,&created) || !created)) return 22;
        int width=snprintf(invalid,sizeof invalid,"%s/%s",path,names[i]);
        if(width<=0 || (size_t)width>=sizeof invalid || qpc_marker_read(invalid)!=(i ? -1 : 0)) return 23;
    }
    WCHAR cleanup_names[][32]={L"input-\u4e2d\u6587",L"wrong-marker",L"long-marker"};
    for(size_t i=0;i<3;++i) {
        HANDLE file=qpc_file_relative(directory,cleanup_names[i],wcslen(cleanup_names[i]),DELETE,0,0,NULL);
        FILE_DISPOSITION_INFO disposition={TRUE};
        if(file==INVALID_HANDLE_VALUE || !SetFileInformationByHandle(file,FileDispositionInfo,&disposition,sizeof disposition)
           || !CloseHandle(file)) return 24;
    }
    if(!FlushFileBuffers(directory) || !CloseHandle(directory)) return 25;
    puts("WINDOWS_INPUT_PASS unicode=true extended_separator=true held_publisher_read=true mandatory_lock_preserved=true missing_pending=true malformed_refused=true");
    return 0;
}
static int qpc_consumer_main(int argc,char **argv) {
    if(argc!=2) return 64;
    int result=run(argv[1]);
    if(result) fprintf(stderr,"Windows input control failed: stage=%d error=%lu\n",result,(unsigned long)GetLastError());
    return result;
}
#include "consumer_entry.h"
