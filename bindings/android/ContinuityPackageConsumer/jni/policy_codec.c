/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "policy_codec.h"
#include <string.h>

uint32_t qpj_policy_u32(const uint8_t *p) {
    uint32_t value = 0;
    for (size_t i = 0; i < 4; ++i) value = (value << 8) | p[i];
    return value;
}
uint64_t qpj_policy_u64(const uint8_t *p) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}
void qpj_policy_put32(uint8_t *p, uint32_t value) {
    for (size_t i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (24 - i * 8));
}
void qpj_policy_put64(uint8_t *p, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) p[i] = (uint8_t)(value >> (56 - i * 8));
}
void qpj_policy_document(qpc_policy_document_v1 *out, const owned_bytes *in) {
    memcpy(out->family, in[0].data, 32); out->root = in[1].data; out->root_length = in[1].length;
    out->version = qpj_policy_u64(in[2].data); memcpy(out->digest, in[3].data, 32);
    out->wire = in[4].data; out->wire_length = in[4].length;
}
void qpj_policy_pin(qpc_account_pin_v1 *out, const owned_bytes *in) {
    memcpy(out->account, in[0].data, 32); out->root = in[1].data; out->root_length = in[1].length;
    memcpy(out->family, in[2].data, 32); out->checkpoint.version = qpj_policy_u64(in[3].data);
    memcpy(out->checkpoint.digest, in[4].data, 32);
}
static void checkpoint_write(uint8_t *p, uint64_t version, const uint8_t digest[32]) {
    qpj_policy_put64(p, version); memcpy(p + 8, digest, 32);
}
static void scope_encode(uint8_t *p, const qpc_policy_renewal_scope_v1 *s) {
    memcpy(p, s->operation, 32); memcpy(p + 32, s->journal, 32); memcpy(p + 64, s->original_owner, 32);
    memcpy(p + 96, s->original_credential, 32); memcpy(p + 128, s->current_credential, 32);
    checkpoint_write(p + 160, s->current_roster.version, s->current_roster.digest);
    checkpoint_write(p + 200, s->original_policy.version, s->original_policy.digest);
    checkpoint_write(p + 240, s->previous_policy.version, s->previous_policy.digest);
    memcpy(p + 280, s->previous_authorization, 32);
    qpj_policy_put32(p + 312, s->has_previous_authorization); qpj_policy_put32(p + 316, s->reserved);
}
static void scope_decode(qpc_policy_renewal_scope_v1 *s, const uint8_t *p) {
    memcpy(s->operation, p, 32); memcpy(s->journal, p + 32, 32); memcpy(s->original_owner, p + 64, 32);
    memcpy(s->original_credential, p + 96, 32); memcpy(s->current_credential, p + 128, 32);
    s->current_roster.version = qpj_policy_u64(p + 160); memcpy(s->current_roster.digest, p + 168, 32);
    s->original_policy.version = qpj_policy_u64(p + 200); memcpy(s->original_policy.digest, p + 208, 32);
    s->previous_policy.version = qpj_policy_u64(p + 240); memcpy(s->previous_policy.digest, p + 248, 32);
    memcpy(s->previous_authorization, p + 280, 32);
    s->has_previous_authorization = qpj_policy_u32(p + 312); s->reserved = qpj_policy_u32(p + 316);
}
void qpj_policy_request_encode(uint8_t *p, const qpc_policy_renewal_request_v1 *r) {
    scope_encode(p, &r->scope); memcpy(p + 320, r->account, 32);
    checkpoint_write(p + 352, r->original_roster_checkpoint.version, r->original_roster_checkpoint.digest);
    const qpc_public_record_v1 *records[] = {&r->original_credential, &r->original_roster, &r->current_credential, &r->current_roster};
    for (size_t i = 0; i < 4; ++i) {
        uint8_t *record = p + 392 + i * 8196;
        qpj_policy_put32(record, records[i]->length); memcpy(record + 4, records[i]->bytes, 8192);
    }
}
int qpj_policy_request_decode(qpc_policy_renewal_request_v1 *r, const uint8_t *p) {
    scope_decode(&r->scope, p); memcpy(r->account, p + 320, 32);
    r->original_roster_checkpoint.version = qpj_policy_u64(p + 352);
    memcpy(r->original_roster_checkpoint.digest, p + 360, 32);
    qpc_public_record_v1 *records[] = {&r->original_credential, &r->original_roster, &r->current_credential, &r->current_roster};
    for (size_t i = 0; i < 4; ++i) {
        const uint8_t *record = p + 392 + i * 8196;
        uint32_t length = qpj_policy_u32(record);
        if (length == 0 || length > 8192) return 0;
        for (size_t tail = length; tail < 8192; ++tail) if (record[4 + tail] != 0) return 0;
        records[i]->length = length; memcpy(records[i]->bytes, record + 4, 8192);
    }
    return 1;
}
void qpj_policy_status_encode(uint8_t *p, const qpc_policy_renewal_status_v1 *s) {
    qpj_policy_put32(p, s->phase); qpj_policy_put32(p + 4, s->reason);
    memcpy(p + 8, s->operation, 32); memcpy(p + 40, s->statement, 32);
    checkpoint_write(p + 72, s->target.version, s->target.digest);
    checkpoint_write(p + 112, s->observed_roster.version, s->observed_roster.digest);
    qpj_policy_put64(p + 152, s->observed_at);
}
