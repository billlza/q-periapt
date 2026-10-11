/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Guarded short options and separately compiled C layouts. No lifecycle claim. */
#if defined(__linux__)
#define _DEFAULT_SOURCE 1
#endif
#include "qpc_owner.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

_Static_assert(sizeof(qpc_root_scope_v1) == 128, "scope layout");
_Static_assert(offsetof(qpc_root_scope_v1, checkpoint) == 8, "scope checkpoint");
_Static_assert(sizeof(qpc_root_alternative_v1) == 72, "alternative layout");
_Static_assert(offsetof(qpc_root_alternative_v1, original) == 8, "alternative input");

int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page < 128) return 1;
    size_t span = (size_t)page;
    uint8_t *mapping = mmap(NULL, span * 2, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED) return 2;
    if (mprotect(mapping + span, span, PROT_NONE) != 0) return 3;
    /* Readable aligned size prefix ends immediately before the guarded page. */
    uint8_t *prefix = mapping + span - 8;
    uint32_t short_size = 4;
    memcpy(prefix, &short_size, sizeof(short_size));
    uint8_t *proposal = malloc(QPC_ROOT_PROPOSAL_CAPACITY);
    if (proposal == NULL) return 4;
    memset(proposal, 0x5a, QPC_ROOT_PROPOSAL_CAPACITY);
    size_t written = 99;
    qpc_error_v1 error = {0};
    qpc_authority_checkpoint_v1 checkpoint = {0};
    checkpoint.revision = 99;
    if (qpc_root_v1_begin(0, 1, (const qpc_root_scope_v1 *)(const void *)prefix,
                          NULL, SIZE_MAX, &error) != QPC_ARGUMENT) return 5;
    if (qpc_root_v1_transition(0, (const qpc_root_alternative_v1 *)(const void *)prefix,
                               proposal, QPC_ROOT_PROPOSAL_CAPACITY, &written,
                               &error) != QPC_ARGUMENT || written != 0) return 6;
    if (qpc_root_v1_adopt(0, (const qpc_root_alternative_v1 *)(const void *)prefix,
                         &checkpoint, &error) != QPC_ARGUMENT ||
        checkpoint.revision != 99) return 7;
    for (size_t i = 0; i < QPC_ROOT_PROPOSAL_CAPACITY; ++i) {
        if (proposal[i] != 0x5a) return 8;
    }
    free(proposal);
    if (munmap(mapping, span * 2) != 0) return 9;
    puts("ROOT_C_CONTRACT guarded_short_scope=true guarded_short_alternative=true outputs_preserved=true lifecycle_qualified=false");
    return 0;
}
