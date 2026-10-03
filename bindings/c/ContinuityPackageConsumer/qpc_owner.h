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
 * Ordinary calls share one absolute 20-second deadline, captured at admission,
 * across construction, witness exchanges, listener wait, application TLS and
 * control TLS. Phase-specific bounds may shorten it. Filesystem operations,
 * cryptographic work and host callbacks are synchronous and cooperative: the
 * deadline is checked at boundaries, not an OS preemption guarantee. A native
 * error is retained even if time also expired; late success requires original-ID
 * reconciliation. Failed constructors publish no handle and release their slot.
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
    QPC_RESOURCE_LIMIT = 4, QPC_INTERNAL = 5, QPC_OWNER_KIND = 6,
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
enum {
    QPC_ACCOUNT_ABSENT = 0, QPC_ACCOUNT_RESERVED = 1, QPC_ACCOUNT_COMMITTED = 2,
    QPC_ACCOUNT_ABANDONING = 3, QPC_ACCOUNT_ABANDONED = 4, QPC_ACCOUNT_RETIRED = 5
};
enum {
    QPC_ACCOUNT_CONFIRMED = 1, QPC_ACCOUNT_PREFIX_PENDING = 2,
    QPC_ACCOUNT_RESOLUTION_PENDING = 3, QPC_ACCOUNT_DELIVERY_UNKNOWN = 4,
    QPC_ACCOUNT_HISTORY_RETIRED = 5, QPC_ACCOUNT_RESERVATION_ABANDONED = 6
};
typedef struct {
    uint64_t peer;
    uint8_t session[32];
} qpc_account_target_v1;
typedef struct {
    uint8_t device[16];
    uint8_t session[32];
    uint8_t message[32];
    uint32_t outcome;
    uint32_t exchanges;
} qpc_account_delivered_v1;

#ifdef __cplusplus
extern "C" {
#endif
/* Device-parent operations. next_account only reads the original journal's next
 * ID; retain it before submitting. status describes LOCAL aggregate state and
 * returns the exact 32-byte report only for ABANDONING/ABANDONED (otherwise zero).
 * COMMITTED is not remote delivery. Cancelled/closed parent admission still fails.
 * Send copies 1..32 aligned targets, each a distinct live child of this exact
 * parent with a distinct nonzero session. selected is a zero-based array index.
 * Every current recipient in the account's signed roster is required; the local
 * sender is excluded only for its own account. All peers remain locked and owned
 * for the call. Any member cancel signals this invocation, preserving other
 * owners' permanent tokens; any member close/operation returns BUSY. The parent
 * also remains BUSY. Idle peers outside the set keep their independent lifetime.
 * The native journal admits the complete original input before each attempt;
 * this function never decomposes the transaction into unary sends. Each call
 * delivers ONE selected member. Retain the same ID, account, complete set and
 * input across retries and other members. Remote effects are not atomic.
 * Zero exchanges reports an already retained outcome, which may be unknown or
 * retired, not necessarily consumed. Failure/cancel may follow local/remote
 * commit. No pointer is retained after return. id/account are 32 readable bytes.
 */
int32_t qpc_device_v1_next_account(uint64_t parent, uint8_t id[32], qpc_error_v1 *error);
int32_t qpc_device_v1_account_status(uint64_t parent, const uint8_t id[32],
                                   uint8_t *status, uint8_t report[32], qpc_error_v1 *error);
int32_t qpc_device_v1_send_account_member(uint64_t parent,
    const qpc_account_target_v1 *targets, size_t count, size_t selected,
    const uint8_t id[32], const uint8_t account[32],
    const uint8_t *peer, size_t peer_length,
    const uint8_t *plaintext, size_t plaintext_length,
    const uint8_t *ad, size_t ad_length,
    qpc_account_delivered_v1 *delivered, qpc_error_v1 *error);
/* path is an absolute UTF-8 private ORIGINAL consumer configuration directory,
 * no embedded NUL. This API opens existing stores only. It never provisions,
 * replaces pins, repairs files or downgrades required-witness protection.
 * quality is independently caller-selected: 1=one-time both, 2=reusable both,
 * 3=signed classical + one-time PQ, 4=one-time classical + last-resort PQ.
 * Ordinary open consumes local-profile installations; required protection needs
 * the explicit witnessed constructor and otherwise returns its admission error.
 * Both signing/key owners are loaded from their protected original files.
 * The config format is a qualification fixture, not a frozen product provisioning API.
 */
typedef struct {
    const uint8_t *address;
    size_t address_length;
    uint32_t timeout_ms;
} qpc_witness_v1;
/* Explicit existing witness, never enrollment or fallback. The exact numeric
 * socket address is caller-selected; original witness-id/witness-public pins and
 * device signing owner come from the protected installation. timeout_ms is
 * 1..10000 per native authenticated exchange. Options/bytes are borrowed only
 * for construction. The signed TCP carrier authenticates but does not encrypt
 * public metadata. Connected reads/writes check cancellation between socket calls
 * with at most 25-ms timeouts, subject to OS scheduling. Pending connects also
 * check cancellation while retaining the attempt's original deadline.
 * Witness errors retain their native unknown-outcome status, not retry permission.
 */
int32_t qpc_owner_v1_open_witness(const uint8_t *path, size_t length, uint8_t quality,
                                const qpc_witness_v1 *witness, uint64_t *handle, qpc_error_v1 *error);
/* Explicit encrypted carrier; same address, deadline and signing-pin contract.
 * Protected original files: witness-tls-cert (DER leaf), witness-tls-key (DER
 * private key), witness-tls-peer (exact trusted server DER leaf), witness-tls-name
 * (UTF-8 DNS name or IP). Certificates/keys are bounded to 8192 bytes, name to 128.
 * Mutual TLS 1.3 requires X25519MLKEM768 and ALPN q-periapt-anchor/1, fresh full
 * handshakes, CA/name validation AND exact leaf pinning. No automatic fallback.
 * Classical certificates are not PQ identity authentication. The original dual
 * witness signatures still authorize commands/replies. TLS credentials are
 * independent of application TLS credentials and SDK operational permission.
 */
int32_t qpc_owner_v1_open_witness_tls(const uint8_t *path, size_t length, uint8_t quality,
                                    const qpc_witness_v1 *witness, uint64_t *handle, qpc_error_v1 *error);
int32_t qpc_owner_v1_open(const uint8_t *path, size_t length, uint8_t quality,
                        uint64_t *handle, qpc_error_v1 *error);
/* Two-stage opening for caller-controlled cancellation during activation.
 * prepare_open validates/copies bounded inputs only; it performs no installation
 * I/O and returns a pending handle occupying the SAME 64-owner registry. Retained
 * path/options are owned copies; all caller input regions may be released after
 * preparation. Path validity, trust, policy and durable state are checked only
 * by finish_open. This step does not provision or grant operational authority.
 * kind: 1=pairwise operational, 2=recovery, 3=device parent.
 * quality: 1..4 for pairwise operational; 0 for recovery/device parent.
 * carrier: 0=original local profile (witness MUST be NULL), 1=signed TCP,
 * 2=mutual TLS (witness MUST reference valid qpc_witness_v1). No fallback.
 * finish_open runs synchronously on its calling thread with a fresh single
 * 20-second invocation deadline. Another thread may cancel using the known
 * handle; competing finish/operations/close return BUSY while it is active.
 * Pending handles reject business operations with OWNER_KIND. An admitted
 * initialization consumes the request once: any initialization failure leaves
 * the handle closed to all work, while cancel/close remain available. Close it
 * before preparing the SAME original installation to reconcile uncertain work.
 * Admission failures (BUSY/call CAPACITY) do not consume a pending request.
 * Success converts the same handle into the selected owner; a second finish
 * returns OWNER_KIND. Idle pending handles can be cancelled/closed immediately.
 * No background task is created. Native failures retain their typed status;
 * cancellation cannot preempt arbitrary filesystem/cryptographic kernel work.
 */
typedef struct {
    uint32_t kind;
    uint32_t quality;
    uint32_t carrier;
    const qpc_witness_v1 *witness;
} qpc_open_options_v1;
int32_t qpc_owner_v1_prepare_open(const uint8_t *path, size_t length,
                                const qpc_open_options_v1 *options,
                                uint64_t *handle, qpc_error_v1 *error);
/* Explicit installation setup over independently provisioned original key,
 * signing, local-* credential/roster, SDK/protocol policy and TLS configuration.
 * Both preparations copy bounded inputs without I/O and require kind=3, quality=0.
 * finish_open then either CREATEs a new durable Creating intent (refusing existing
 * children/configuration), or RESUMEs only an existing original Creating/Active
 * intent. An error or missing file never selects the other action. This interface
 * does not generate/enroll keys, issue credentials or install trust from peers.
 *
 * status returns phase 1=Creating or 2=Active and its original public journal ID.
 * prepare_storage is Creating-only: it creates genuinely missing initial children
 * or verifies the exact original empty genesis. Existing partial/conflicting files
 * fail; no file is removed, repaired or replaced. protection=1 is the signed
 * local-only profile, with zero subject/digest; protection=2 requires independent
 * enrollment of the exact 96-byte subject and 32-byte initial image digest under
 * the ORIGINAL witness. These are public enrollment inputs, not signed receipts
 * or enrollment permission. Repeating successful preparation preserves the ID.
 *
 * activate consumes setup, admits the original witness and commits Active before
 * converting the SAME handle to a device parent. Required protection cannot fall
 * back to local-only. A missing/unavailable witness returns its native error.
 * On admitted activation failure, only cancel/close remain; reopen with
 * prepare_resume to reconcile original durable state, which may already be Active.
 * Setup status/preparation after successful activation returns OWNER_KIND.
 * Active setup can activate existing children but cannot prepare replacements.
 * All stages share the owner/call quotas, one-way cancellation, exclusive call
 * ownership and deadlines above. Setup itself grants no peer/message authority.
 * Creating/Active status does not extend credential, policy or roster validity.
 */
typedef struct {
    uint32_t phase;
    uint8_t journal[32];
} qpc_setup_status_v1;
typedef struct {
    uint32_t protection;
    uint8_t journal[32];
    uint8_t subject[96];
    uint8_t image_digest[32];
} qpc_setup_preparation_v1;
int32_t qpc_setup_v1_prepare_create(const uint8_t *path, size_t length,
                                  const qpc_open_options_v1 *options,
                                  uint64_t *handle, qpc_error_v1 *error);
int32_t qpc_setup_v1_prepare_resume(const uint8_t *path, size_t length,
                                  const qpc_open_options_v1 *options,
                                  uint64_t *handle, qpc_error_v1 *error);
int32_t qpc_setup_v1_status(uint64_t handle, qpc_setup_status_v1 *status,
                          qpc_error_v1 *error);
int32_t qpc_setup_v1_prepare_storage(uint64_t handle, qpc_setup_preparation_v1 *preparation,
                                   qpc_error_v1 *error);
int32_t qpc_setup_v1_activate(uint64_t handle, qpc_error_v1 *error);
/* A device parent opens only an already Active original installation using its
 * independently configured local-* identity, SDK/protocol policy and witness.
 * It does not read a bootstrap bundle, select a peer, provision, or activate a
 * Creating record. Transport credentials are retained once and validated with
 * each peer's exact pin before the child is published. Parent handles expose
 * cancel/close and child preparation, not pairwise protocol operations.
 *
 * Peer preparation copies path/quality/role and retains the device control owner;
 * it performs no I/O and does not acquire another storage lease. quality is 1..4;
 * role is 1=local initiator, 2=local responder. Peer files contain independently
 * retained initiator/responder pins, directory expectation, bootstrap.bundle,
 * tls-peer and tls-peer-name. Incoming bundle bytes cannot select those pins.
 * finish_open verifies all inputs against the original parent and publishes the
 * child at the same handle. prepare_reopen additionally copies a nonzero 32-byte
 * original session ID; fresh admission never falls back to restoration.
 *
 * Admitted peers use the ordinary operational functions below. Parent and every
 * prepared/live peer consume the same 64-owner quota. Peer operations serialize
 * on their device service; conflicting operations return BUSY. An idle sibling
 * can close while another peer is active, without taking that service lock.
 * Parent close returns BUSY while a child call is active. Cancel the parent and
 * join that call before close: cancellation signals the active child's call and
 * fences every future child call. Cancelling one child does not cancel its parent
 * or siblings. Successful parent close releases storage even with idle children;
 * their future operations return CLOSED. Close those children to reclaim slots.
 * Closing a peer never retires a session, acknowledges work, or closes its parent.
 * Parent closure after preparation can make finish_open fail without authority.
 * All inputs and writable output/error regions must be distinct and nonoverlapping.
 */
int32_t qpc_peer_v1_prepare(uint64_t parent, const uint8_t *path, size_t length,
                           uint32_t quality, uint32_t role,
                           uint64_t *handle, qpc_error_v1 *error);
int32_t qpc_peer_v1_prepare_reopen(uint64_t parent, const uint8_t *path, size_t length,
                                  uint32_t quality, uint32_t role,
                                  const uint8_t session[32], uint64_t *handle,
                                  qpc_error_v1 *error);
/* Explicit restoration of a nonzero existing session. options.kind must be 1;
 * quality and witness carrier retain the same independent-selection contract.
 * Preparation copies all inputs without installation I/O. session is exactly
 * 32 readable immutable bytes. finish_open requires the original Active stores,
 * exact established session/role/context and closure archive, current authority
 * and required witness. It may authenticate expired public advertisement/roster
 * snapshots but never extends credential/policy validity or creates new state.
 * The fresh constructors do not automatically use this path after any failure.
 */
int32_t qpc_owner_v1_prepare_reopen(const uint8_t *path, size_t length,
                                  const qpc_open_options_v1 *options, const uint8_t session[32],
                                  uint64_t *handle, qpc_error_v1 *error);
int32_t qpc_owner_v1_finish_open(uint64_t handle, qpc_error_v1 *error);
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
 * Accept and serving retain one 20-second invocation deadline and the carrier's
 * 8-exchange bound. Cancel wakes accept polling within 25 ms, subject
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
/* Cleanup-only original-installation owner. Shares the same 64-owner/call
 * budgets and generic close/cancel functions, but operational calls return
 * OWNER_KIND. Ordinary open loads no live SDK policy, TLS credential or signer.
 * Discovery IDs are hints; select authenticates the original journal/key/archive.
 * Required-witness selection still refuses admission without its original witness.
 * A failed native selection consumes/closes discovery; reopen the ORIGINAL input.
 * No function provisions, rewinds, repairs or grants sending permission.
 */
enum { QPC_CLOSURE_ARCHIVE_BYTES = 362 };
typedef struct {
    uint64_t peer_generation, confirmed_epoch, sending_epoch, receiving_epoch, pending_epoch;
    uint32_t has_pending_epoch, role, reserved_count, epoch_count;
    uint8_t session[32], context[32], report[32], peer_account[32], peer_device[16];
} qpc_closure_header_v1;
typedef struct {
    uint64_t epoch, acknowledged_before, sent, consumed_before, received, peer_sent;
    uint32_t has_peer_sent, resolution, unconfirmed_count, delivery_count, skipped_count, reserved_zero;
    uint8_t resolution_report[32];
} qpc_closure_epoch_v1;
typedef struct {
    uint64_t plaintext_bytes, associated_data_bytes;
    uint8_t message[32];
} qpc_closure_reserved_v1;
typedef struct { uint8_t message[32], ciphertext_digest[32]; } qpc_closure_unconfirmed_v1;
typedef struct { uint64_t index, plaintext_bytes; uint8_t message[32]; } qpc_closure_delivery_v1;
typedef struct { uint32_t phase; uint8_t report[32]; } qpc_closure_status_v1;
/* status: 0=open,1=pending,2=closed. resolution: 0=unrequested,1=pending,
 * 2=acknowledged. Optional counters are meaningful only with their presence flag.
 * Skipped positions do not prove corresponding peer messages existed.
 * Ciphertext digests are the native domain-separated ciphertext commitments,
 * never plaintext/content hashes. These records contain no application plaintext.
 * Raw struct bytes are not a portable serialization; hosts encode every field.
 *
 * begin permanently freezes an independent session and retains its complete
 * immutable report. Read ALL reserved/epoch/nested entries before acknowledging.
 * Getters read that snapshot, not new network authority or a refreshed lifecycle.
 * Persist the complete report + ID in a durable deduplicated host transaction.
 * Only then acknowledge that same ID. Unknown commit/cancellation requires
 * original-ID reopen/status reconciliation, never a new report or empty default.
 * retire removes catalogue metadata only after exact closed-state admission;
 * it neither deletes the journal tombstone nor refunds identity/key budgets.
 * Export/retain the authenticated archive before retiring the catalogue row.
 * select_archive + restore_index restores metadata only, never operational keys.
 * Cached report/metadata queries remain available after cancel. Fresh witnessed
 * status admission can fail when cancellation prevents its required exchange;
 * close and reopen original state to reconcile it. Mutations check cancellation
 * before/after native work but cannot preempt an arbitrary filesystem/socket call.
 */
int32_t qpc_recovery_v1_open(const uint8_t *path, size_t length, uint64_t *handle, qpc_error_v1 *error);
/* Witnessed cleanup retains only the original device signer for native witness
 * requests, not operational SDK permission. Selection authenticates original
 * required-witness state even for already closed sessions and archived metadata.
 */
int32_t qpc_recovery_v1_open_witness(const uint8_t *path, size_t length,
                                   const qpc_witness_v1 *witness, uint64_t *handle, qpc_error_v1 *error);
/* Same cleanup-only authority, using the explicit witness TLS files above. */
int32_t qpc_recovery_v1_open_witness_tls(const uint8_t *path, size_t length,
                                       const qpc_witness_v1 *witness, uint64_t *handle, qpc_error_v1 *error);
int32_t qpc_recovery_v1_session_count(uint64_t handle, uint32_t *count, qpc_error_v1 *error);
int32_t qpc_recovery_v1_session_at(uint64_t handle, uint32_t index, uint8_t session[32], qpc_error_v1 *error);
int32_t qpc_recovery_v1_select(uint64_t handle, const uint8_t session[32], qpc_error_v1 *error);
int32_t qpc_recovery_v1_select_archive(uint64_t handle, const uint8_t *archive, size_t length, qpc_error_v1 *error);
int32_t qpc_recovery_v1_archive(uint64_t handle, uint8_t archive[QPC_CLOSURE_ARCHIVE_BYTES], qpc_error_v1 *error);
int32_t qpc_recovery_v1_begin(uint64_t handle, qpc_closure_header_v1 *header, qpc_error_v1 *error);
int32_t qpc_recovery_v1_status(uint64_t handle, qpc_closure_status_v1 *status, qpc_error_v1 *error);
int32_t qpc_recovery_v1_reserved(uint64_t handle, uint32_t index, qpc_closure_reserved_v1 *record, qpc_error_v1 *error);
int32_t qpc_recovery_v1_epoch(uint64_t handle, uint32_t index, qpc_closure_epoch_v1 *record, qpc_error_v1 *error);
int32_t qpc_recovery_v1_unconfirmed(uint64_t handle, uint32_t epoch, uint32_t index, qpc_closure_unconfirmed_v1 *record, qpc_error_v1 *error);
int32_t qpc_recovery_v1_delivery(uint64_t handle, uint32_t epoch, uint32_t index, qpc_closure_delivery_v1 *record, qpc_error_v1 *error);
int32_t qpc_recovery_v1_skipped(uint64_t handle, uint32_t epoch, uint32_t index, uint64_t *position, qpc_error_v1 *error);
int32_t qpc_recovery_v1_acknowledge(uint64_t handle, const uint8_t report[32], qpc_error_v1 *error);
int32_t qpc_recovery_v1_retire(uint64_t handle, const uint8_t report[32], uint8_t *removed, qpc_error_v1 *error);
int32_t qpc_recovery_v1_restore_index(uint64_t handle, qpc_error_v1 *error);

/* Complete-account recovery uses the same original discovery owner and explicit
 * witness constructors above. select_account consumes discovery; the authenticated
 * journal chooses ALL original members. It accepts no recipient list or replacement
 * peer context. Failed native selection stays closed. Original installation scope
 * and every member archive must authenticate before any pending write is resolved.
 * Required protection keeps the original witness/policy/signer; no local fallback.
 * A selected account rejects independent-session methods with QPC_STATE and has no
 * operational API. Close/cancel retain the existing owner/call lifetime contract.
 *
 * begin freezes the entire reserved batch and retains one immutable report. Ordinary
 * committed batches cannot be relabeled as reserved abandonment. Read every member,
 * its ONE reserved input, every epoch and every nested list before acknowledging.
 * Member order is the original canonical device order; all indices are zero-based.
 * Persist every field plus the batch/report IDs in a durable deduplicated host
 * transaction. Raw C struct bytes are not a serialization. Only then acknowledge
 * the exact report. Metadata retirement requires prior acknowledgement and keeps
 * every session/bootstrap tombstone and the journal counter. Repeating retirement
 * on the same owner is idempotent; authenticated reopen returns QPC_RETIRED after
 * retirement and QPC_DURABLE_ABSENT for a genuinely absent original operation.
 * Unknown commit/cancel requires exact original-ID reopen/status reconciliation.
 * Cached member/epoch queries remain available after cancel. Required-witness
 * status is fresh native admission and may fail; it cannot silently use a cache.
 * Status uses QPC_ACCOUNT_* values, not independent-session closure phases.
 */
typedef struct {
    uint8_t batch[32], report[32];
    uint32_t member_count, reserved_zero;
} qpc_account_cleanup_header_v1;
typedef struct {
    uint64_t generation, confirmed_epoch, sending_epoch, receiving_epoch, pending_epoch;
    uint32_t has_pending_epoch, role, epoch_count, reserved_zero;
    uint8_t device[16], context[32], session[32];
} qpc_account_cleanup_member_v1;
typedef struct { uint32_t phase; uint8_t report[32]; } qpc_account_cleanup_status_v1;
int32_t qpc_recovery_v1_select_account(uint64_t handle, const uint8_t id[32], qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_begin(uint64_t handle, qpc_account_cleanup_header_v1 *header, qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_status(uint64_t handle, qpc_account_cleanup_status_v1 *status, qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_member(uint64_t handle, uint32_t member, qpc_account_cleanup_member_v1 *record, qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_reserved(uint64_t handle, uint32_t member, qpc_closure_reserved_v1 *record, qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_epoch(uint64_t handle, uint32_t member, uint32_t epoch, qpc_closure_epoch_v1 *record, qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_unconfirmed(uint64_t handle, uint32_t member, uint32_t epoch, uint32_t index, qpc_closure_unconfirmed_v1 *record, qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_delivery(uint64_t handle, uint32_t member, uint32_t epoch, uint32_t index, qpc_closure_delivery_v1 *record, qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_skipped(uint64_t handle, uint32_t member, uint32_t epoch, uint32_t index, uint64_t *position, qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_acknowledge(uint64_t handle, const uint8_t report[32], qpc_error_v1 *error);
int32_t qpc_recovery_v1_account_retire(uint64_t handle, qpc_error_v1 *error);
#ifdef __cplusplus
}
#endif
#endif
