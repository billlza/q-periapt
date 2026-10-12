/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPJ_RECOVERY_WIRE_H
#define QPJ_RECOVERY_WIRE_H
#include "bridge.h"
#include <string.h>

/* Explicit big-endian fields; never memcpy padded C records into Java. */
static inline void qpj_rw32(uint8_t *out, uint32_t value) {
    for (size_t i=0;i<4;i++) out[i]=(uint8_t)(value>>(24-8*i));
}
static inline void qpj_rw64(uint8_t *out, uint64_t value) {
    for (size_t i=0;i<8;i++) out[i]=(uint8_t)(value>>(56-8*i));
}
static inline void qpj_rw_reservation(uint8_t *out, const qpc_closure_reserved_v1 *value) {
    qpj_rw64(out,value->plaintext_bytes);qpj_rw64(out+8,value->associated_data_bytes);memcpy(out+16,value->message,32);
}
static inline void qpj_rw_epoch(uint8_t *out, const qpc_closure_epoch_v1 *value) {
    qpj_rw64(out,value->epoch);qpj_rw64(out+8,value->acknowledged_before);qpj_rw64(out+16,value->sent);
    qpj_rw64(out+24,value->consumed_before);qpj_rw64(out+32,value->received);qpj_rw64(out+40,value->peer_sent);
    qpj_rw32(out+48,value->has_peer_sent);qpj_rw32(out+52,value->resolution);
    qpj_rw32(out+56,value->unconfirmed_count);qpj_rw32(out+60,value->delivery_count);
    qpj_rw32(out+64,value->skipped_count);qpj_rw32(out+68,value->reserved_zero);memcpy(out+72,value->resolution_report,32);
}
static inline void qpj_rw_delivery(uint8_t *out, const qpc_closure_delivery_v1 *value) {
    qpj_rw64(out,value->index);qpj_rw64(out+8,value->plaintext_bytes);memcpy(out+16,value->message,32);
}
int32_t qpj_recovery_account(uint64_t, jint, const uint8_t *, uint32_t, uint32_t, uint32_t, uint8_t *, qpc_error_v1 *);
int32_t qpj_recovery_session(uint64_t, jint, const uint8_t *, uint32_t, uint32_t, uint8_t *, qpc_error_v1 *);
#endif
