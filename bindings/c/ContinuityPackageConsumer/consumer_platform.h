/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_CONSUMER_PLATFORM_H
#define QPC_CONSUMER_PLATFORM_H
/* Native caller threads and monotonic observations for the reference clients. */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
_Static_assert(sizeof(time_t)>=sizeof(int64_t), "Windows caller clock requires 64-bit time_t");
typedef HANDLE qpc_thread;
struct qpc_thread_call {
    void *(*function)(void *);
    void *argument;
};
static unsigned __stdcall qpc_thread_entry(void *opaque) {
    struct qpc_thread_call *call=opaque;
    void *(*function)(void *)=call->function;
    void *argument=call->argument;
    free(call);
    (void)function(argument);
    return 0;
}
static inline int qpc_thread_start(qpc_thread *thread, void *(*function)(void *), void *argument) {
    struct qpc_thread_call *call=malloc(sizeof *call);
    if(!call) return ENOMEM;
    call->function=function; call->argument=argument;
    uintptr_t handle=_beginthreadex(NULL,0,qpc_thread_entry,call,0,NULL);
    if(!handle) {
        int error=errno;
        free(call);
        return error ? error : EIO;
    }
    *thread=(HANDLE)handle;
    return 0;
}
static inline int qpc_thread_join(qpc_thread thread) {
    DWORD waited=WaitForSingleObject(thread,INFINITE);
    int closed=CloseHandle(thread)!=0;
    return waited==WAIT_OBJECT_0 && closed ? 0 : EIO;
}
static inline int qpc_monotonic_time(struct timespec *value) {
    LARGE_INTEGER ticks, frequency;
    if(!QueryPerformanceCounter(&ticks) || !QueryPerformanceFrequency(&frequency)
       || ticks.QuadPart<0 || frequency.QuadPart<=0) return -1;
    /* Divide out whole seconds before conversion to retain subsecond precision
     * at long uptimes. Normalize the possible rounded fractional endpoint. */
    int64_t seconds=ticks.QuadPart/frequency.QuadPart;
    int64_t remainder=ticks.QuadPart%frequency.QuadPart;
    long nanos=(long)((long double)remainder*1000000000.0L/(long double)frequency.QuadPart);
    if(nanos==1000000000L) {
        if(seconds==INT64_MAX) return -1;
        ++seconds; nanos=0;
    }
    value->tv_sec=(time_t)seconds; value->tv_nsec=nanos;
    return 0;
}
static inline int qpc_sleep(const struct timespec *interval) {
    if(interval->tv_sec<0 || interval->tv_nsec<0 || interval->tv_nsec>=1000000000L
       || (uint64_t)interval->tv_sec>(UINT32_MAX-1u)/1000u) { errno=EINVAL; return -1; }
    uint64_t wanted=(uint64_t)interval->tv_sec*1000000000u+(uint64_t)interval->tv_nsec;
    uint64_t remaining=wanted;
    if((wanted+999999u)/1000000u>=INFINITE) { errno=EINVAL; return -1; }
    struct timespec start,now;
    if(qpc_monotonic_time(&start)) { errno=EIO; return -1; }
    for(;;) {
        Sleep((DWORD)((remaining+999999u)/1000000u));
        if(qpc_monotonic_time(&now) || now.tv_sec<start.tv_sec
           || (now.tv_sec==start.tv_sec && now.tv_nsec<start.tv_nsec)) { errno=EIO; return -1; }
        uint64_t seconds=(uint64_t)now.tv_sec-(uint64_t)start.tv_sec;
        if(seconds>(uint64_t)interval->tv_sec+1u) return 0;
        int64_t elapsed=(int64_t)(seconds*1000000000u)+now.tv_nsec-start.tv_nsec;
        if((uint64_t)elapsed>=wanted) return 0;
        /* Sleep's scheduler tick may wake early; retain nanosleep's minimum
         * delay using the same monotonic observation as caller deadlines. */
        remaining=wanted-(uint64_t)elapsed;
    }
}
#else
#include <pthread.h>
typedef pthread_t qpc_thread;
static inline int qpc_thread_start(qpc_thread *thread, void *(*function)(void *), void *argument) {
    return pthread_create(thread,NULL,function,argument);
}
static inline int qpc_thread_join(qpc_thread thread) { return pthread_join(thread,NULL); }
static inline int qpc_monotonic_time(struct timespec *value) { return clock_gettime(CLOCK_MONOTONIC,value); }
static inline int qpc_sleep(const struct timespec *interval) { return nanosleep(interval,NULL); }
#endif
#endif
