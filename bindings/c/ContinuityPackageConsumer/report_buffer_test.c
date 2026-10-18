/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
static int allocation_failure;
static void *test_realloc(void *pointer, size_t size) {
    return allocation_failure ? NULL : realloc(pointer,size);
}
#define realloc test_realloc
#include "report_buffer.h"
#undef realloc
#include <inttypes.h>

int main(void) {
    struct qpc_report_buffer out={0};
    if(qpc_report_ready(&out)) return 1;
    uint8_t bytes[]={0x00,0x09,0x0a,0x10,0x7f,0x80,0xfe,0xff};
    qpc_report_puts(&out,"report "); qpc_report_hex(&out,bytes,sizeof bytes);
    qpc_report_putc(&out,'\n');
    qpc_report_printf(&out,"members %u index %" PRIu64 " signed %d\n",32u,UINT64_MAX,-1);
    const char expected[]="report 00090a107f80feff\nmembers 32 index 18446744073709551615 signed -1\n";
    if(!qpc_report_ready(&out) || out.length!=sizeof(expected)-1
       || memcmp(out.data,expected,sizeof expected)) return 2;
#ifndef _WIN32
    /* Independent libc stream oracle for the original report representation. */
    char *original=NULL; size_t length=0;
    FILE *stream=open_memstream(&original,&length);
    if(!stream) return 3;
    int bad=fputs("report ",stream)<0;
    for(size_t i=0;i<sizeof bytes;++i) if(fprintf(stream,"%02x",bytes[i])<0) bad=1;
    if(fputc('\n',stream)==EOF
       || fprintf(stream,"members %u index %" PRIu64 " signed %d\n",32u,UINT64_MAX,-1)<0) bad=1;
    if(fclose(stream)) bad=1;
    if(bad || length!=out.length || memcmp(original,out.data,length+1)) return 4;
    free(original);
#endif
    qpc_report_dispose(&out);
    char block[1025]; memset(block,'x',sizeof block-1); block[sizeof block-1]=0;
    for(size_t i=0;i<QPC_REPORT_LIMIT/(sizeof block-1);++i) qpc_report_puts(&out,block);
    if(!qpc_report_ready(&out) || out.length!=QPC_REPORT_LIMIT || out.data[out.length]) return 5;
    for(size_t i=0;i<out.length;++i) if(out.data[i]!='x') return 6;
    qpc_report_putc(&out,'!');
    qpc_report_printf(&out,"%s","must not resume after failure");
    if(qpc_report_ready(&out) || !out.failed || out.length!=QPC_REPORT_LIMIT
       || out.data[out.length] || out.data[out.length-1]!='x') return 7;
    qpc_report_dispose(&out);
    qpc_report_printf(&out,"%*s",(int)QPC_REPORT_LIMIT+1,"");
    if(qpc_report_ready(&out) || !out.failed || out.data || out.length) return 8;
    qpc_report_dispose(&out);
    /* Reject before reading bytes or multiplying a caller-supplied hex length. */
    qpc_report_hex(&out,bytes,SIZE_MAX);
    if(qpc_report_ready(&out) || !out.failed || out.data || out.length) return 9;
    qpc_report_dispose(&out);
    qpc_report_puts(&out,"original prefix");
    if(!qpc_report_ready(&out)) return 10;
    allocation_failure=1;
    qpc_report_puts(&out,block);
    allocation_failure=0;
    qpc_report_putc(&out,'!');
    if(qpc_report_ready(&out) || !out.failed || strcmp(out.data,"original prefix")
       || out.length!=sizeof("original prefix")-1) return 11;
    qpc_report_dispose(&out);
    puts("REPORT_BUFFER_PASS canonical_bytes=true size_limit=true failure_sticky=true");
    return 0;
}
