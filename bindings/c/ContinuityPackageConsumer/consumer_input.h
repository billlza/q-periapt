/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_CONSUMER_INPUT_H
#define QPC_CONSUMER_INPUT_H
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
static inline FILE *qpc_input_file(const char *path) {
    int length=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,NULL,0);
    if(length<=0) { errno=EINVAL; return NULL; }
    WCHAR *wide=malloc((size_t)length*sizeof *wide);
    if(!wide) { errno=ENOMEM; return NULL; }
    if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,wide,length)!=length) {
        free(wide); errno=EINVAL; return NULL;
    }
    FILE *file=NULL; int error=_wfopen_s(&file,wide,L"rb");
    free(wide); if(error) errno=error;
    return file;
}
static inline int qpc_input_seek(FILE *file, int64_t offset, int origin) { return _fseeki64(file,offset,origin); }
static inline int64_t qpc_input_position(FILE *file) { return _ftelli64(file); }
#else
#include <sys/types.h>
static inline FILE *qpc_input_file(const char *path) { return fopen(path,"rb"); }
static inline int qpc_input_seek(FILE *file, int64_t offset, int origin) {
    off_t native=(off_t)offset;
    if((int64_t)native!=offset) { errno=EOVERFLOW; return -1; }
    return fseeko(file,native,origin);
}
static inline int64_t qpc_input_position(FILE *file) { return (int64_t)ftello(file); }
#endif
#endif
