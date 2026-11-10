/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Native control for exact read-only images while the original lock is held. */
#include <errno.h>
#include <stdio.h>
#include "consumer_input.h"
#include "live_image_windows.h"

static const unsigned char body[]="original bytes under an exclusive live owner";
static const char name[]="live-image-probe";

/* Execute the old stdio image sequence and preserve the failing operation. */
static int crt_read(const char *path,int phase,DWORD expected_error) {
    errno=0; SetLastError(ERROR_SUCCESS);
    if(_set_doserrno(0)) return -1;
    FILE *file=qpc_input_file(path);
    int stage=1;
    unsigned char buffer[sizeof body];
    if(file) {
        stage=2;
        if(!qpc_input_seek(file,0,SEEK_END)) {
            stage=3;
            if(qpc_input_position(file)==(int64_t)(sizeof body-1)) {
                stage=4;
                if(!qpc_input_seek(file,0,SEEK_SET)) {
                    stage=5;
                    if(fread(buffer,1,sizeof body-1,file)==sizeof body-1
                       && !memcmp(buffer,body,sizeof body-1) && fgetc(file)==EOF && !ferror(file)) stage=0;
                }
            }
        }
    }
    int error=errno; DWORD native=GetLastError(); unsigned long dos=0;
    if(_get_doserrno(&dos)) { if(file) (void)fclose(file); return -1; }
    int closed=file ? fclose(file) : 0;
    printf("WINDOWS_LIVE_IMAGE_CRT phase=%d success=%d stage=%d errno=%d native=%lu dos=%lu closed=%d\n",
           phase,stage==0,stage,error,(unsigned long)native,dos,closed);
    if(closed) return -1;
    if(expected_error) return stage!=0 && (native==expected_error || dos==expected_error) ? 0 : -1;
    return stage==0 ? 0 : -1;
}

static int writer_refused(HANDLE observer) {
    OVERLAPPED position={0};
    BOOL acquired=LockFileEx(observer,LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,
                             0,MAXDWORD,MAXDWORD,&position);
    DWORD error=GetLastError();
    if(acquired) {
        if(!UnlockFileEx(observer,0,MAXDWORD,MAXDWORD,&position)) return -1;
        return -1;
    }
    return error==ERROR_LOCK_VIOLATION ? 0 : -1;
}

static int live_image_probe(int argc,char **argv) {
    if(argc!=2) return 64;
    WCHAR leaf[]=L"live-image-probe";
    int created=0;
    if(qpc_file_commit(argv[1],name,body,sizeof body-1,&created) || !created) return 10;
    char path[8192]; int n=snprintf(path,sizeof path,"%s/%s",argv[1],name);
    if(n<=0 || (size_t)n>=sizeof path || crt_read(path,0,ERROR_SUCCESS)) return 11;
    HANDLE directory=qpc_file_directory(argv[1]);
    if(directory==INVALID_HANDLE_VALUE) return 12;
    HANDLE holder=qpc_file_relative(directory,leaf,wcslen(leaf),GENERIC_READ|GENERIC_WRITE,0,0,NULL);
    if(holder==INVALID_HANDLE_VALUE) return 13;
    /* The secure CRT reader itself denies sharing with a live writer, before
     * byte-range locking is involved. A native shared reader below separates
     * that condition from the SDK's mandatory lifetime lock. */
    if(crt_read(path,1,ERROR_SHARING_VIOLATION)) return 24;
    OVERLAPPED position={0};
    if(!LockFileEx(holder,LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY,
                   0,MAXDWORD,MAXDWORD,&position)) return 14;
    HANDLE observer=qpc_file_relative(directory,leaf,wcslen(leaf),GENERIC_READ|GENERIC_WRITE,0,0,NULL);
    if(observer==INVALID_HANDLE_VALUE || writer_refused(observer)
       || crt_read(path,2,ERROR_SHARING_VIOLATION)) return 15;
    DWORD count=0; unsigned char byte=0;
    BOOL ordinary=ReadFile(observer,&byte,1,&count,NULL); DWORD read_error=GetLastError();
    if(ordinary || count || read_error!=ERROR_LOCK_VIOLATION) return 16;
    WCHAR wide[8192]; char canonical[32768];
    DWORD width=GetFinalPathNameByHandleW(directory,wide,8192,FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if(!width || width>=8192 || !WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,-1,
                                                  canonical,(int)sizeof canonical,NULL,NULL)) return 17;
    const char *roots[2]={argv[1],canonical};
    for(size_t i=0;i<2;++i) {
        unsigned char *image=NULL; size_t length=0;
        if(!qpc_live_image_read(roots[i],name,sizeof body-2,&image,&length) || image || length) return 18;
        if(qpc_live_image_read(roots[i],name,sizeof body-1,&image,&length)
           || length!=sizeof body-1 || memcmp(image,body,length)) return 19;
        free(image);
        if(writer_refused(observer)) return 20;
    }
    if(!UnlockFileEx(holder,0,MAXDWORD,MAXDWORD,&position) || !CloseHandle(observer) || !CloseHandle(holder)) return 21;
    struct qpc_private_record record;
    unsigned char after[sizeof body];
    if(qpc_record_open(&record,argv[1],name,sizeof body-1,0)
       || qpc_record_read(&record,after,sizeof after) || qpc_record_close(&record)
       || memcmp(after,body,sizeof body-1)) return 22;
    HANDLE cleanup=qpc_file_relative(directory,leaf,wcslen(leaf),DELETE,0,0,NULL);
    FILE_DISPOSITION_INFO disposition={TRUE};
    if(cleanup==INVALID_HANDLE_VALUE || !SetFileInformationByHandle(cleanup,FileDispositionInfo,&disposition,sizeof disposition)
       || !CloseHandle(cleanup) || !FlushFileBuffers(directory) || !CloseHandle(directory)) return 23;
    puts("WINDOWS_LIVE_IMAGE_PASS bounded=true original_bytes=true original_lock_held=true ordinary_read_refused=true competing_writer_refused=true verbatim_path=true");
    return 0;
}
static int qpc_consumer_main(int argc,char **argv) {
    int result=live_image_probe(argc,argv);
    if(result) fprintf(stderr,"live image control failed: stage=%d error=%lu\n",result,(unsigned long)GetLastError());
    return result;
}
#include "consumer_entry.h"
