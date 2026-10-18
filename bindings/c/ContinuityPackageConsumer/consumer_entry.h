/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_CONSUMER_ENTRY_H
#define QPC_CONSUMER_ENTRY_H
/* Include after the reference caller's qpc_consumer_main definition. Windows
 * supplies Unicode arguments; the existing C/SDK path contract consumes UTF-8. */
#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
int wmain(int argc,wchar_t **argv) {
    if(argc<=0) return 64;
    /* Machine-readable records keep the existing UTF-8/LF byte contract;
     * Windows CRT text mode would translate each LF into CRLF. */
    if(_setmode(_fileno(stdout),_O_BINARY)==-1 || _setmode(_fileno(stderr),_O_BINARY)==-1) return 64;
    char **utf8=calloc((size_t)argc+1,sizeof *utf8);
    if(!utf8) return 64;
    int result=64;
    for(int i=0;i<argc;++i) {
        int size=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[i],-1,NULL,0,NULL,NULL);
        if(size<=0) goto done;
        utf8[i]=malloc((size_t)size);
        if(!utf8[i] || WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,argv[i],-1,utf8[i],size,NULL,NULL)!=size) goto done;
    }
    result=qpc_consumer_main(argc,utf8);
done:
    for(int i=0;i<argc;++i) free(utf8[i]);
    free(utf8); return result;
}
#else
int main(int argc,char **argv) { return qpc_consumer_main(argc,argv); }
#endif
#endif
