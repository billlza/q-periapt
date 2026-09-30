/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#ifndef QPC_OWNER_V1_H
#define QPC_OWNER_V1_H
#include <stddef.h>
#include <stdint.h>

/* Unpublished candidate consumer ABI qpc-owner/1, distinct from product ABI 2.
 * Handles are process-local owners, not permissions against hostile same-process
 * code. IDs never repeat within this loaded consumer. Its registry holds at most
 * 64 active or constructing owners and 64 ordinary calls admitted before buffer
 * copying; these are not cross-library global quotas. Close/cancel are exempt
 * from call capacity so that callers can drain it.
 * An active call returns BUSY to competing operations/close. cancel is concurrent,
 * one-way and applies to later invocations too. Cancel, join, close and reopen the
 * SAME original installation to resume an uncertain operation.
 *
 * All inputs must be readable and unchanged for the call's exact stated length.
 * Outputs and the error record cannot be shared by concurrent calls. All outputs must be
 * writable and aligned. Output regions (including error) must not overlap any
 * other input/output region. Zero-length plaintext/AD allow a null input pointer.
 * No pointer is retained after the call. Arbitrary invalid C addresses are UB.
 * Error is mandatory and belongs to this call; it is not thread-local state.
 * Other outputs are meaningful only on return zero. Nonzero return never proves
 * absence, non-dispatch or lack of peer commitment.
 * Query the same ID; never replace it to hide an unknown outcome.
 */
typedef struct {
    int32_t code;
    uint32_t length;
    uint32_t truncated;
    uint8_t message[512]; /* UTF-8 bytes, NOT NUL-terminated */
} qpc_error_v1;

enum {
    QPC_OK = 0, QPC_ARGUMENT = 1, QPC_CLOSED = 2, QPC_BUSY = 3,
    QPC_RESOURCE_LIMIT = 4, QPC_INTERNAL = 5,
    QPC_ENCODING = 101, QPC_AUTHENTICATION = 102, QPC_SCOPE = 103,
    QPC_VALIDITY = 104, QPC_CHECKPOINT = 105, QPC_POLICY_DENIED = 106,
    QPC_INPUT_CONFLICT = 107, QPC_STATE = 108,
    QPC_PROTOCOL_CAPACITY = 110, QPC_REKEY_REQUIRED = 111, QPC_RETIRED = 112,
    QPC_POLICY_CLOSED = 113, QPC_ENTROPY = 114, QPC_PROVIDER = 115,
    QPC_DURABLE_ABSENT = 201, QPC_DURABLE_CLOSED = 202, QPC_PRIVATE_FILE = 203,
    QPC_DATABASE = 204, QPC_STORAGE_IO = 205, QPC_STORAGE = 206,
    QPC_COMMIT_UNCERTAIN = 207, QPC_IMAGE_AUTHENTICATION = 208,
    QPC_CORRUPT = 209, QPC_INVALID_CHECKPOINT = 210, QPC_SCOPE_CONFLICT = 211,
    QPC_PREKEY_CLAIMED = 212, QPC_KEY_RETIRED = 213, QPC_CAPACITY = 214,
    QPC_SUSPENDED = 215, QPC_ANCHOR_REQUIRED = 216, QPC_ARCHIVE_REQUIRED = 217,
    QPC_ANCHOR = 218, QPC_REJECTED = 219,
    QPC_OPTIONS = 301, QPC_CANCELLED = 302, QPC_DEADLINE = 303,
    QPC_ATTEMPTS = 304, QPC_BINDING = 305, QPC_CARRIER = 306,
    QPC_CLOCK = 307, QPC_APPLICATION = 308, QPC_TLS = 309,
    QPC_NETWORK = 310, QPC_RETRY_EXHAUSTED = 311,
    QPC_CONFIGURATION = 500,
    QPC_SDK_CLOSED = 601, QPC_SDK_LENGTH = 602, QPC_SDK_POLICY_DENIED = 603,
    QPC_SDK_KEY_SHARE = 604, QPC_SDK_ENTROPY = 605, QPC_SDK_RESOURCE = 606,
    QPC_SDK_LIMITS = 607, QPC_SDK_PURPOSE = 608, QPC_SDK_PRIVATE_KEY = 609,
    QPC_SDK_BACKEND = 610,
    QPC_HOST_CLOSED = 701, QPC_HOST_PRIVATE_FILE = 702, QPC_HOST_BUSY = 703,
    QPC_HOST_CORRUPT = 704, QPC_HOST_ROOT = 705, QPC_HOST_STALE = 706,
    QPC_HOST_IO = 708, QPC_HOST_STORAGE = 709, QPC_HOST_COMMIT_UNCERTAIN = 710,
    QPC_HOST_ACTIVATION_AFTER_COMMIT = 711, QPC_HOST_UNSUPPORTED_ERROR = 712
};
/* Archive errors add 1000 to their underlying status. Diagnostic text retains
 * nested local error causes. A code is a reason, never an automatic-retry policy. */
enum {
    QPC_MESSAGE_ABSENT = 0, QPC_MESSAGE_RESERVED = 1, QPC_MESSAGE_COMMITTED = 2,
    QPC_MESSAGE_ACKNOWLEDGED = 3, QPC_MESSAGE_RESOLUTION_PENDING = 4,
    QPC_MESSAGE_DELIVERY_UNKNOWN = 5, QPC_MESSAGE_RESERVATION_ABANDONED = 6
};
enum { QPC_CONSUMPTION_CONFIRMED = 1, QPC_CONSUMPTION_PREFIX_PENDING = 2 };

#ifdef __cplusplus
extern "C" {
#endif
/* path is an absolute UTF-8 private ORIGINAL consumer configuration directory,
 * no embedded NUL. This API opens existing stores only. It never provisions,
 * replaces pins, repairs files or downgrades required-witness protection.
 * quality is independently caller-selected: 1=one-time both, 2=reusable both,
 * 3=signed classical + one-time PQ, 4=one-time classical + last-resort PQ.
 * This initial client consumes local-profile installations; required protection
 * returns its actual admission error. Required-witness adapter remains unfinished.
 * Both signing/key owners are loaded from their protected original files.
 * The config format is a qualification fixture, not a frozen product provisioning API.
 */
int32_t qpc_owner_v1_open(const uint8_t *path, size_t length, uint8_t quality,
                        uint64_t *handle, qpc_error_v1 *error);
int32_t qpc_owner_v1_cancel(uint64_t handle, qpc_error_v1 *error);
int32_t qpc_owner_v1_close(uint64_t handle, qpc_error_v1 *error);
/* peer is an explicit IP:port socket address (IPv6 uses brackets); TLS server
 * name and certificate pin come from the independent protected configuration.
 * Each invocation retains 8 total attempts/20 seconds/1-second connect bounds.
 */
int32_t qpc_owner_v1_establish(uint64_t handle, const uint8_t *peer, size_t peer_length,
                             const uint8_t request[32], uint8_t session[32],
                             uint16_t *exchanges, qpc_error_v1 *error);
int32_t qpc_owner_v1_next_message(uint64_t handle, const uint8_t session[32],
                                uint8_t message[32], qpc_error_v1 *error);
int32_t qpc_owner_v1_send(uint64_t handle, const uint8_t *peer, size_t peer_length,
                        const uint8_t session[32], const uint8_t message[32],
                        const uint8_t *plaintext, size_t plaintext_length,
                        const uint8_t *ad, size_t ad_length, uint8_t *consumption,
                        uint16_t *exchanges, qpc_error_v1 *error);
int32_t qpc_owner_v1_message_status(uint64_t handle, const uint8_t session[32],
                                  const uint8_t message[32], uint8_t *status,
                                  qpc_error_v1 *error);
int32_t qpc_owner_v1_rekey(uint64_t handle, const uint8_t *peer, size_t peer_length,
                         const uint8_t session[32], uint64_t target,
                         uint64_t *completed_epoch, qpc_error_v1 *error);
/* One listener belongs to the owner and closes with it. address is an explicit
 * IP:port; zero port requests an ephemeral port. Repeated listen returns STATE.
 * Serving waits at most 20 seconds for accept, then uses the shared carrier's
 * 20-second/8-exchange bound. Cancel wakes accept polling within 25 ms, subject
 * to OS scheduling. Synchronous application/filesystem calls are cooperative;
 * the library cannot preempt a foreign callback or undo its effects.
 */
int32_t qpc_owner_v1_listen(uint64_t handle, const uint8_t *address, size_t length,
                          uint16_t *port, qpc_error_v1 *error);
typedef struct {
    uint32_t kind; /* 1=bootstrap, 2=consumed message */
    uint8_t session[32];
    uint8_t message[32]; /* zero for bootstrap */
    uint32_t duplicate; /* 1=already consumed; callback was not invoked */
} qpc_served_v1;
/* Borrowed immutable session/message/plaintext pointers expire on return.
 * context remains caller-owned and must live until serve returns. The callback
 * runs synchronously on the invoking thread and must not unwind or longjmp.
 * Return zero ONLY after effect and session/message deduplication record are
 * durable together. Every nonzero result (including unknown commit) leaves the
 * inbox unconsumed and returns APPLICATION with the callback status in diagnostics.
 * Exact retries may invoke the callback again; it must reconcile the same ID.
 * No callback pointer/context is stored past serve. Reentrant operations/close
 * return BUSY; cancellation is allowed with a separate per-call error record.
 */
typedef int32_t (*qpc_commit_v1)(void *context, const uint8_t session[32],
                               const uint8_t message[32], const uint8_t *plaintext,
                               size_t length);
int32_t qpc_owner_v1_serve(uint64_t handle, qpc_commit_v1 commit, void *context,
                         qpc_served_v1 *result, qpc_error_v1 *error);
int32_t qpc_owner_v1_serve_rekey(uint64_t handle, const uint8_t session[32],
                               uint64_t *completed_epoch, qpc_error_v1 *error);
#ifdef __cplusplus
}
#endif
#endif
