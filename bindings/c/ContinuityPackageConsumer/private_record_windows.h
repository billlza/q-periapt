/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_PRIVATE_RECORD_WINDOWS_H
#define QPC_PRIVATE_RECORD_WINDOWS_H
#include "private_files_windows.h"

/* A bounded record and its original parent remain pinned through read/sync.
 * Call close on every successfully opened record, including after read failure. */
struct qpc_private_record { HANDLE directory, file; size_t length; int synchronize; };
static inline int qpc_record_close(struct qpc_private_record *record) {
    int bad=0;
    if(record->file!=INVALID_HANDLE_VALUE && !CloseHandle(record->file)) bad=1;
    if(record->directory!=INVALID_HANDLE_VALUE && !CloseHandle(record->directory)) bad=1;
    record->file=record->directory=INVALID_HANDLE_VALUE;
    return bad ? -1 : 0;
}
static inline int qpc_record_open(struct qpc_private_record *record, const char *path,
                                 const char *name, size_t maximum, int synchronize) {
    *record=(struct qpc_private_record){INVALID_HANDLE_VALUE,INVALID_HANDLE_VALUE,0,synchronize};
    WCHAR wide[256];
    int width=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,-1,wide,256);
    if(width<=0 || qpc_file_leaf(wide,(size_t)width-1)) return -1;
    record->directory=qpc_file_directory(path);
    if(record->directory==INVALID_HANDLE_VALUE) return -1;
    record->file=qpc_file_relative(record->directory,wide,(size_t)width-1,
        GENERIC_READ|(synchronize ? GENERIC_WRITE : 0),0,0,NULL);
    BY_HANDLE_FILE_INFORMATION info;
    if(record->file==INVALID_HANDLE_VALUE || qpc_file_information(record->file,0,&info)
       || qpc_file_private(record->file) || info.nFileSizeHigh
       || !info.nFileSizeLow || info.nFileSizeLow>maximum) {
        (void)qpc_record_close(record); return -1;
    }
    record->length=info.nFileSizeLow;
    return 0;
}
static inline int qpc_record_read(struct qpc_private_record *record, uint8_t *bytes, size_t capacity) {
    if(record->file==INVALID_HANDLE_VALUE || capacity<record->length) return -1;
    size_t used=0;
    while(used<record->length) {
        DWORD count=0;
        if(!ReadFile(record->file,bytes+used,(DWORD)(record->length-used),&count,NULL)
           || !count || count>record->length-used) return -1;
        used+=count;
    }
    uint8_t extra; DWORD count=0;
    if(!ReadFile(record->file,&extra,1,&count,NULL) || count) return -1;
    if(record->synchronize && (!FlushFileBuffers(record->file)
       || qpc_file_private(record->directory) || !FlushFileBuffers(record->directory))) return -1;
    return 0;
}
static inline int qpc_record_retain(const char *path, const char *name, const uint8_t *bytes,
                                   size_t length, int create) {
    if(!length || length>1048576) return -1;
    if(create) {
        int created=0;
        return qpc_file_commit(path,name,bytes,length,&created);
    }
    WCHAR wide[256];
    int width=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,name,-1,wide,256);
    if(width<=0 || qpc_file_leaf(wide,(size_t)width-1)) return -1;
    HANDLE directory=qpc_file_directory(path);
    if(directory==INVALID_HANDLE_VALUE) return -1;
    int result=qpc_file_existing(directory,wide,bytes,length);
    if(!CloseHandle(directory)) return -1;
    return result==0 ? 0 : -1;
}
#endif
