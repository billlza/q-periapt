/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _POSIX_C_SOURCE 200809L
#include "consumer_platform.h"
#include <stdio.h>

struct Call { unsigned ran; int failed; struct timespec before, after; };
static void *worker(void *opaque) {
    struct Call *call=opaque;
    const struct timespec pause={0,25000000};
    call->failed=qpc_monotonic_time(&call->before)!=0;
    if(!call->failed) {
        while(qpc_sleep(&pause)) {
            if(errno!=EINTR) { call->failed=1; break; }
        }
    }
    if(qpc_monotonic_time(&call->after)) call->failed=1;
    call->ran=1;
    return NULL;
}
int main(void) {
    struct Call call={0}; qpc_thread thread;
    if(qpc_thread_start(&thread,worker,&call) || qpc_thread_join(thread)) return 1;
    if(call.ran!=1 || call.failed || call.before.tv_nsec<0 || call.before.tv_nsec>=1000000000L
       || call.after.tv_nsec<0 || call.after.tv_nsec>=1000000000L
       || call.after.tv_sec<call.before.tv_sec
       || (call.after.tv_sec==call.before.tv_sec && call.after.tv_nsec<=call.before.tv_nsec)) return 2;
    time_t seconds=call.after.tv_sec-call.before.tv_sec;
    if(seconds<=1 && (int64_t)seconds*1000000000+call.after.tv_nsec-call.before.tv_nsec<25000000) return 3;
    puts("CONSUMER_PLATFORM_PASS native_worker_join=true monotonic_clock=true sleep_completed=true");
    return 0;
}
