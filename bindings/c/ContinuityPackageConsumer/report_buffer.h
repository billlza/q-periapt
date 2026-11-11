/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_REPORT_BUFFER_H
#define QPC_REPORT_BUFFER_H
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Recovery reports already have this serialized size limit. Keep the bytes in
 * memory until the caller publishes them with its existing durable file path.
 * Zero-initialize a buffer; after any failure it stays invalid until disposed. */
#define QPC_REPORT_LIMIT ((size_t)1048576)
struct qpc_report_buffer {
    char *data;
    size_t length, capacity;
    int failed;
};
static inline int qpc_report_reserve(struct qpc_report_buffer *out, size_t extra) {
    if(out->failed) return -1;
    if(extra>QPC_REPORT_LIMIT-out->length) { out->failed=1; return -1; }
    size_t needed=out->length+extra+1;
    if(needed<=out->capacity) return 0;
    size_t capacity=out->capacity ? out->capacity : 256;
    while(capacity<needed)
        capacity=capacity>(QPC_REPORT_LIMIT+1)/2 ? QPC_REPORT_LIMIT+1 : capacity*2;
    char *data=realloc(out->data,capacity);
    if(!data) { out->failed=1; return -1; }
    out->data=data; out->capacity=capacity; out->data[out->length]=0;
    return 0;
}
static inline void qpc_report_puts(struct qpc_report_buffer *out, const char *text) {
    size_t length=strlen(text);
    if(qpc_report_reserve(out,length)) return;
    memcpy(out->data+out->length,text,length+1); out->length+=length;
}
static inline void qpc_report_putc(struct qpc_report_buffer *out, char value) {
    if(qpc_report_reserve(out,1)) return;
    out->data[out->length++]=value; out->data[out->length]=0;
}
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static inline void qpc_report_printf(struct qpc_report_buffer *out, const char *format, ...) {
    if(out->failed) return;
    va_list args, copy;
    va_start(args,format); va_copy(copy,args);
    int length=vsnprintf(NULL,0,format,copy);
    va_end(copy);
    if(length<0) out->failed=1;
    else if(!qpc_report_reserve(out,(size_t)length)) {
        int written=vsnprintf(out->data+out->length,(size_t)length+1,format,args);
        if(written!=length) out->failed=1;
        else out->length+=(size_t)length;
    }
    va_end(args);
}
static inline void qpc_report_hex(struct qpc_report_buffer *out, const uint8_t *bytes, size_t length) {
    static const char digits[]="0123456789abcdef";
    if(length>QPC_REPORT_LIMIT/2) { out->failed=1; return; }
    if(qpc_report_reserve(out,length*2)) return;
    for(size_t i=0;i<length;++i) {
        out->data[out->length++]=digits[bytes[i]>>4];
        out->data[out->length++]=digits[bytes[i]&15];
    }
    out->data[out->length]=0;
}
static inline int qpc_report_ready(const struct qpc_report_buffer *out) {
    return !out->failed && out->length>0 && out->length<=QPC_REPORT_LIMIT;
}
static inline void qpc_report_dispose(struct qpc_report_buffer *out) {
    free(out->data);
    *out=(struct qpc_report_buffer){0};
}
#endif
