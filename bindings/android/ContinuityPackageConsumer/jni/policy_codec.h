/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPERIAPT_ANDROID_POLICY_CODEC_H
#define QPERIAPT_ANDROID_POLICY_CODEC_H
#include "bridge.h"
enum { QPJ_POLICY_REQUEST_BYTES = 33176, QPJ_POLICY_APPROVAL_BYTES = 7618 };
uint32_t qpj_policy_u32(const uint8_t *);
uint64_t qpj_policy_u64(const uint8_t *);
void qpj_policy_put32(uint8_t *, uint32_t);
void qpj_policy_put64(uint8_t *, uint64_t);
void qpj_policy_document(qpc_policy_document_v1 *, const owned_bytes *);
void qpj_policy_pin(qpc_account_pin_v1 *, const owned_bytes *);
/* Exactly QPJ_POLICY_REQUEST_BYTES readable/writable bytes; no struct casts. */
int qpj_policy_request_decode(qpc_policy_renewal_request_v1 *, const uint8_t *);
void qpj_policy_request_encode(uint8_t *, const qpc_policy_renewal_request_v1 *);
void qpj_policy_status_encode(uint8_t *, const qpc_policy_renewal_status_v1 *);
#endif
