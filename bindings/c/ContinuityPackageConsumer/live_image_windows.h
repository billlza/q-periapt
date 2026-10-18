/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_LIVE_IMAGE_WINDOWS_H
#define QPC_LIVE_IMAGE_WINDOWS_H
#include "private_record_windows.h"

/* Test-only observation of a quiescent, still-owned database. Windows byte
 * locks prohibit ordinary reads through another handle but permit mapped
 * views. Keep the SDK lock intact and grant this observer read access only.
 * https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-lockfileex */
static inline int qpc_live_image_read(const char *path,const char *name,size_t maximum,
                                      unsigned char **bytes,size_t *length) {
    *bytes=NULL; *length=0;
    struct qpc_private_record record;
    if(qpc_record_open(&record,path,name,maximum,0)) return -1;
    unsigned char *copy=malloc(record.length);
    HANDLE mapping=NULL; const void *view=NULL;
    int stage=0; DWORD error=ERROR_SUCCESS;
    if(!copy) { stage=-2; error=ERROR_NOT_ENOUGH_MEMORY; }
    if(!stage) {
        mapping=CreateFileMappingW(record.file,NULL,PAGE_READONLY,0,0,NULL);
        if(!mapping) { stage=-3; error=GetLastError(); }
    }
    if(!stage) {
        view=MapViewOfFile(mapping,FILE_MAP_READ,0,0,record.length);
        if(!view) { stage=-4; error=GetLastError(); }
    }
    if(!stage) {
        memcpy(copy,view,record.length);
        BY_HANDLE_FILE_INFORMATION info;
        if(qpc_file_information(record.file,0,&info) || info.nFileSizeHigh
           || info.nFileSizeLow!=record.length) { stage=-5; error=ERROR_INVALID_DATA; }
    }
    if(view && !UnmapViewOfFile(view) && !stage) { stage=-6; error=GetLastError(); }
    if(mapping && !CloseHandle(mapping) && !stage) { stage=-7; error=GetLastError(); }
    if(qpc_record_close(&record) && !stage) { stage=-8; error=GetLastError(); }
    if(stage) { free(copy); SetLastError(error); return stage; }
    *bytes=copy; *length=record.length;
    return 0;
}
#endif
