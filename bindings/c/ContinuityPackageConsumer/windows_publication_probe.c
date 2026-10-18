/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Isolated native rename experiment. This never selects a production fallback. */
#include <stdio.h>
#include "private_files_windows.h"
/* winternl.h exposes only part of the WDK native information interface.
 * Match the documented ntifs.h signature and FileRenameInformation (10):
 * https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile
 * https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information */
__declspec(dllimport) NTSTATUS NTAPI NtSetInformationFile(
    HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
struct native_rename {
    union { BOOLEAN replace; ULONG flags; } action;
    HANDLE directory;
    ULONG name_bytes;
    WCHAR name[1];
};
_Static_assert(sizeof(FILE_INFORMATION_CLASS)==4, "native information class width");
_Static_assert(offsetof(struct native_rename,directory)==8
    && offsetof(struct native_rename,name_bytes)==16
    && offsetof(struct native_rename,name)==20 && sizeof(struct native_rename)==24,
    "supported Windows 64-bit native rename layout");
_Static_assert(offsetof(FILE_RENAME_INFO,RootDirectory)==8
    && offsetof(FILE_RENAME_INFO,FileNameLength)==16
    && offsetof(FILE_RENAME_INFO,FileName)==20 && sizeof(FILE_RENAME_INFO)==24,
    "compare the same native and Win32 field layout");

static int native_publish(HANDLE file,HANDLE directory,WCHAR *name,DWORD *error) {
    size_t count=wcslen(name), size=(sizeof(struct native_rename)+(count+1)*sizeof(WCHAR)+7)&~(size_t)7;
    struct native_rename *info=calloc(1,size);
    if(!info) return -1;
    info->action.replace=FALSE;
    info->directory=directory; info->name_bytes=(ULONG)(count*sizeof(WCHAR));
    memcpy(info->name,name,(count+1)*sizeof(WCHAR));
    IO_STATUS_BLOCK completion={0};
    NTSTATUS status=NtSetInformationFile(file,&completion,info,(ULONG)size,(FILE_INFORMATION_CLASS)10);
    /* The source was opened with synchronous non-alertable I/O. Never replace
     * a failing primary status with an unfilled zero completion status. */
    *error=RtlNtStatusToDosError(status!=0 ? status : completion.Status);
    int success=status==0 && completion.Status==0;
    printf("WINDOWS_NATIVE_RENAME_STATUS primary=%08lx completion=%08lx\n",
        (unsigned long)(ULONG)status,(unsigned long)(ULONG)completion.Status);
    free(info); return success;
}
static int write_control(HANDLE file,const uint8_t *bytes,DWORD length) {
    DWORD written=0;
    return WriteFile(file,bytes,length,&written,NULL) && written==length && FlushFileBuffers(file) ? 0 : -1;
}
static int dispose(HANDLE file) {
    FILE_DISPOSITION_INFO disposition={TRUE};
    int bad=!SetFileInformationByHandle(file,FileDispositionInfo,&disposition,sizeof disposition);
    if(!CloseHandle(file)) bad=1;
    return bad ? -1 : 0;
}
static int variant(HANDLE directory,unsigned kind) {
    static const uint8_t bytes[]="rename-control";
    WCHAR target[128],source[160];
    int count=swprintf(target,128,L"application-%064u",kind+32);
    if(count!=76) return 1;
    int source_count=swprintf(source,160,L".%ls.%lu.tmp",target,(unsigned long)GetCurrentProcessId());
    if(source_count<=0 || source_count>=160) return 2;
    HANDLE file=qpc_file_create(directory,source,(size_t)source_count);
    if(file==INVALID_HANDLE_VALUE || write_control(file,bytes,sizeof bytes-1)) return 3;
    DWORD error=0; int success;
    size_t size=kind==0 ? offsetof(FILE_RENAME_INFO,FileName)+((size_t)count+1)*sizeof(WCHAR)
        : (sizeof(FILE_RENAME_INFO)+((size_t)count+1)*sizeof(WCHAR)+7)&~(size_t)7;
    if(kind<2) {
        FILE_RENAME_INFO *info=calloc(1,size);
        if(!info) return 4;
        info->ReplaceIfExists=FALSE;
        info->RootDirectory=directory; info->FileNameLength=(DWORD)((size_t)count*sizeof(WCHAR));
        memcpy(info->FileName,target,((size_t)count+1)*sizeof(WCHAR));
        success=SetFileInformationByHandle(file,FileRenameInfo,info,(DWORD)size)!=0;
        error=success ? ERROR_SUCCESS : GetLastError(); free(info);
    } else {
        success=native_publish(file,directory,target,&error);
        if(success<0) return 5;
    }
    int original=qpc_file_existing(directory,source,bytes,sizeof bytes-1);
    int published=qpc_file_existing(directory,target,bytes,sizeof bytes-1);
    printf("WINDOWS_RENAME_PROBE variant=%u bytes=%zu success=%d error=%lu source=%d target=%d\n",
        kind,size,success,(unsigned long)error,original,published);
    if(original!=(success ? 1 : 0) || published!=(success ? 0 : 1)) return 6;
    if(kind==2 && success) {
        static const uint8_t other[]="different-control";
        WCHAR collision[]=L".rename-collision.tmp";
        HANDLE second=qpc_file_create(directory,collision,wcslen(collision));
        if(second==INVALID_HANDLE_VALUE || write_control(second,other,sizeof other-1)) return 7;
        int replaced=native_publish(second,directory,target,&error);
        printf("WINDOWS_RENAME_COLLISION success=%d error=%lu\n",replaced,(unsigned long)error);
        if(replaced!=0 || (error!=ERROR_FILE_EXISTS && error!=ERROR_ALREADY_EXISTS)
           || qpc_file_existing(directory,target,bytes,sizeof bytes-1)!=0
           || qpc_file_existing(directory,collision,other,sizeof other-1)!=0) return 8;
        if(dispose(second)) return 9;
    }
    if(dispose(file) || !FlushFileBuffers(directory)) return 10;
    return 0;
}
static int qpc_consumer_main(int argc,char **argv) {
    if(argc!=2) return 64;
    HANDLE directory=qpc_file_directory(argv[1]);
    if(directory==INVALID_HANDLE_VALUE) return 65;
    for(unsigned i=0;i<3;++i) {
        int failure=variant(directory,i);
        if(failure) {
            fprintf(stderr,"rename experiment incomplete: variant=%u stage=%d\n",i,failure);
            (void)CloseHandle(directory); return 66;
        }
    }
    if(!CloseHandle(directory)) return 67;
    puts("WINDOWS_RENAME_EXPERIMENT_COMPLETE publication_admission=false");
    return 0;
}
#include "consumer_entry.h"
