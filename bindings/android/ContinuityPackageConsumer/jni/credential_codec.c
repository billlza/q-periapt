/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#include "credential_codec.h"
#include <string.h>

/* Explicit private JNI framing; native padding is never serialized. */
void qpj_credential_request_encode(uint8_t *out, const qpc_credential_renewal_request_v1 *r) {
    memcpy(out, r->operation, 32); memcpy(out + 32, r->journal, 32);
    memcpy(out + 64, r->original_owner, 32); memcpy(out + 96, r->original_policy_digest, 32);
    qpj_policy_put64(out + 128, r->current_policy.version); memcpy(out + 136, r->current_policy.digest, 32);
    memcpy(out + 168, r->current_policy_authorization, 32);
    qpj_policy_put32(out + 200, r->has_current_policy_authorization); qpj_policy_put32(out + 204, r->reserved);
    qpj_policy_put64(out + 208, r->previous_roster_checkpoint.version); memcpy(out + 216, r->previous_roster_checkpoint.digest, 32);
    qpj_policy_put64(out + 248, r->original_roster_checkpoint.version); memcpy(out + 256, r->original_roster_checkpoint.digest, 32);
    qpj_policy_put64(out + 288, r->previous_valid_from); qpj_policy_put64(out + 296, r->previous_valid_until);
    memcpy(out + 304, r->account, 32);
    const qpc_public_record_v1 *records[] = {&r->original_credential, &r->original_roster, &r->previous_credential, &r->previous_roster};
    for (size_t i = 0; i < 4; ++i) {
        uint8_t *record = out + 336 + i * 8196;
        qpj_policy_put32(record, records[i]->length); memcpy(record + 4, records[i]->bytes, 8192);
    }
}
