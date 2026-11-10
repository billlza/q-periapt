/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_CONSUMER_MARKER_H
#define QPC_CONSUMER_MARKER_H
#include "consumer_input.h"

/* Test synchronization only: absent=0, complete original marker=1, error=-1.
 * Publication exposes complete bytes before closing its writable rename handle.
 * Observe through a shared read handle; never retry malformed or denied inputs. */
static inline int qpc_marker_read(const char *path) {
#ifdef _WIN32
    WCHAR *wide=qpc_path_utf16(path);
    if(!wide) return -1;
    HANDLE file=CreateFileW(wide,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                           NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    DWORD error=GetLastError(); free(wide);
    if(file==INVALID_HANDLE_VALUE) {
        if(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND) return 0;
        SetLastError(error); return -1;
    }
    BY_HANDLE_FILE_INFORMATION info;
    unsigned char bytes[2]; DWORD count=0;
    int result=-1;
    if(!GetFileInformationByHandle(file,&info)) error=GetLastError();
    else if(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)
            || info.nNumberOfLinks!=1 || info.nFileSizeHigh || info.nFileSizeLow!=1)
        error=ERROR_INVALID_DATA;
    else if(!ReadFile(file,bytes,sizeof bytes,&count,NULL)) error=GetLastError();
    else if(count!=1 || bytes[0]!='1') error=ERROR_INVALID_DATA;
    else result=1;
    if(!CloseHandle(file)) { error=GetLastError(); result=-1; }
    if(result<0) SetLastError(error);
    return result;
#else
    FILE *file=qpc_input_file(path);
    if(!file) return errno==ENOENT ? 0 : -1;
    int byte=fgetc(file),end=fgetc(file),bad=ferror(file);
    int closed=fclose(file);
    if(closed || bad) return -1;
    if(byte!='1' || end!=EOF) { errno=EINVAL; return -1; }
    return 1;
#endif
}
#endif
