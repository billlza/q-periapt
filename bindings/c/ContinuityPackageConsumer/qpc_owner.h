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
    QPC_SDK_BACKEND = 610, QPC_SDK_UPDATE_OWNER_REQUIRED = 611,
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

/* Original device registration through the native qperiapt-enrollment/1 owner.
 * This unpublished candidate is separate from product ABI 2. The host supplies
 * an independently approved root and complete device grant, authenticates the
 * account action externally, and transports the returned public request to its
 * authority. Possession of a key/request never grants account membership.
 *
 * Explicit first use: provision_wrapping_key creates only wrap.key and refuses
 * any existing enrollment/signer/installation/journal/archive destination.
 * Existing wrap.key is never replaced. This is not a missing-active-key repair.
 * A failed first creation may have published the key; inspect/reconcile the
 * original first-use operation, never delete it to retry. An already provisioned
 * original key may be used directly by prepare_create/prepare_resume.
 *
 * Both preparations copy all inputs without I/O, require kind=3/quality=0, and
 * retain the explicit carrier. finish_open creates or resumes enrollment.redb
 * under the exact approved intent. Missing/corrupt state never selects create.
 * No pre-generated signer, signer-id, local credential or roster is required.
 * status/request need no SDK policy or TLS files. accept/prepare_storage/refresh
 * require the configured SDK/protocol policy; activate also needs local TLS
 * credentials, and explicit witness pins/credentials if protection requires it.
 *
 * request commits the original signer and exact signed bytes before output;
 * length is the meaningful prefix of bytes, and the unused tail is zero.
 * accept takes untrusted signed response bytes AND a separately trusted current
 * pin. Never derive that pin from the response itself. It commits one original
 * journal ID. prepare_storage returns the same qpc_setup_preparation_v1 contract
 * for separate authorized witness enrollment. No function enrolls the witness.
 *
 * status phases: 1 Preparing, 2 Requested, 3 Accepted, 4 Activating, 5 Active,
 * 6 Refreshing. signing_id is always original; journal is zero only in phases
 * 1/2. previous/next are nonzero only in phase 6. These are durable observations,
 * never live authorization receipts. refresh_roster preserves the credential,
 * key/root/policy and original operation; it cannot renew an expired credential.
 *
 * activate consumes registration and converts this SAME handle to a device
 * parent only after current native policy, roster and required-witness checks.
 * The whole EnrolledDevice and enrollment lease remain owned until parent close.
 * Use peer preparation/reopening on this parent, never legacy installation
 * constructors to bypass original registration. Children borrow its same owners.
 *
 * Admitted registration operation failure closes this handle to all work except
 * cancel/close, releases leases and may leave committed state. Resume the exact
 * original intent; do not recreate keys or IDs. Invalid input shape, wrong owner
 * kind and call-admission Busy/Capacity do not consume it. Cancellation is one-way.
 * A call refused before taking the registration owner retains its lease until
 * close; cancellation observed after admitted work releases it without output.
 * Close cancelled handles and prepare_resume. All existing quotas/deadlines apply.
 */
typedef struct {
    const uint8_t *root;
    size_t root_length;
    uint8_t device[16];
    uint64_t generation;
    uint8_t family[32];
    uint64_t valid_from;
    uint64_t valid_until;
} qpc_enrollment_intent_v1;
typedef struct {
    uint64_t version;
    uint8_t digest[32];
} qpc_roster_checkpoint_v1;
/* Historical renewal axis, separate from enrollment's six phases.
 * phase 0=Absent: all remaining fields zero.
 * phase 1=Pending: operation/statement set, checkpoint/observed_at zero;
 *                this does NOT imply the journal has not committed.
 * phase 2=Committed: operation/statement and historical target checkpoint set,
 *                   observed_at zero; current traffic authority may be denied.
 * phase 3=ExpiredUncommitted: operation/statement, observed journal checkpoint
 *                           and trusted observation time set.
 * phase 4=Closed: exact witness-closed operation/statement and rejected target
 *                 checkpoint set, observed_at zero; preceding authority may live.
 * Output is usable only after success; a nonzero return writes no success fact.
 */
typedef struct {
    uint32_t phase;
    uint8_t operation[32];
    uint8_t statement[32];
    qpc_roster_checkpoint_v1 checkpoint;
    uint64_t observed_at;
} qpc_credential_renewal_status_v1;
typedef struct {
    uint8_t account[32];
    const uint8_t *root;
    size_t root_length;
    uint8_t family[32];
    qpc_roster_checkpoint_v1 checkpoint;
} qpc_account_pin_v1;
typedef struct {
    uint32_t phase;
    uint8_t signing_id[32];
    uint8_t journal[32];
    qpc_roster_checkpoint_v1 previous;
    qpc_roster_checkpoint_v1 next;
} qpc_enrollment_status_v1;
/* Enrollment phase 7=RosterResolved: previous/next retain the ORIGINAL refresh
 * pair (as in phase6), not the observed current head. No operational owner is
 * implied. Resolve that same pair below to read its retained complete outcome.
 * The layout and meanings of phases1..6 are unchanged.
 */
enum {
    QPC_ROSTER_COMMITTED = 1,
    QPC_ROSTER_EXPIRED_UNCOMMITTED = 2,
    QPC_ROSTER_SUPERSEDED_UNCOMMITTED = 3,
    QPC_ROSTER_SUPERSEDED_UNKNOWN = 4
};
/* Historical original-operation result, never a current authorization.
 * All checkpoints/journal/time are present; reserved is zero.
 * 1: observed equals target (exact journal adoption).
 * 2: observed version is below target, whose signed roster has expired.
 * 3: observed has target's version and a different digest, excluding adoption.
 * 4: observed version is above target; past target adoption remains UNKNOWN.
 * previous < target; observed >= previous, with exact equality at same version.
 * The last result survives later activity until another resolution replaces it.
 */
typedef struct {
    uint32_t outcome;
    uint32_t reserved;
    uint8_t journal[32];
    qpc_roster_checkpoint_v1 previous;
    qpc_roster_checkpoint_v1 target;
    qpc_roster_checkpoint_v1 observed;
    uint64_t observed_at;
} qpc_roster_refresh_resolution_v1;
typedef struct {
    uint32_t length;
    uint8_t bytes[8192];
} qpc_enrollment_request_v1;
int32_t qpc_enrollment_v1_provision_wrapping_key(const uint8_t *path, size_t length,
                                               qpc_error_v1 *error);
int32_t qpc_enrollment_v1_prepare_create(const uint8_t *path, size_t length,
    const qpc_enrollment_intent_v1 *intent, const qpc_open_options_v1 *options,
    uint64_t *handle, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_prepare_resume(const uint8_t *path, size_t length,
    const qpc_enrollment_intent_v1 *intent, const qpc_open_options_v1 *options,
    uint64_t *handle, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_status(uint64_t handle, qpc_enrollment_status_v1 *status,
                                qpc_error_v1 *error);
int32_t qpc_enrollment_v1_request(uint64_t handle, qpc_enrollment_request_v1 *request,
                                 qpc_error_v1 *error);
int32_t qpc_enrollment_v1_accept(uint64_t handle,
    const uint8_t *certificate, size_t certificate_length,
    const uint8_t *roster, size_t roster_length, const qpc_account_pin_v1 *pin,
    uint8_t journal[32], qpc_error_v1 *error);
int32_t qpc_enrollment_v1_prepare_storage(uint64_t handle,
    qpc_setup_preparation_v1 *preparation, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_refresh_roster(uint64_t handle,
    const qpc_roster_checkpoint_v1 *previous, const uint8_t *roster, size_t roster_length,
    const qpc_account_pin_v1 *pin, qpc_enrollment_status_v1 *status, qpc_error_v1 *error);
/* Local original-operation metadata only. Original signed policy files are
 * required; SDK/TLS files and private signer are not. A still-live target beyond
 * the actual head stays pending. A newer head never becomes proof of no commit.
 * On success the handle remains an enrollment. On an admitted error, close and
 * resume the original enrollment and retry the same pair; result may be durable.
 * Inputs and outputs obey the disjoint pointer contract. A failure leaves the
 * success output untouched. Required-witness protection is never downgraded.
 */
int32_t qpc_enrollment_v1_resolve_roster_refresh(uint64_t handle,
    const qpc_roster_checkpoint_v1 *previous, const qpc_roster_checkpoint_v1 *target,
    qpc_roster_refresh_resolution_v1 *resolution, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_activate(uint64_t handle, qpc_error_v1 *error);
/* Independently trusted policy pin and signed public document. All pointed
 * regions are immutable, disjoint and readable for the invocation; they are
 * copied before owner admission. Incoming approval bytes cannot select the pin. */
typedef struct {
    const uint8_t *root;
    size_t root_length;
    uint8_t family[32];
    uint64_t version;
    uint8_t digest[32];
    const uint8_t *wire;
    size_t wire_length;
} qpc_policy_document_v1;

/* Independent qperiapt-policy-renewal/1, distinct from joint G/T renewal.
 * These native ABI records are bounded public metadata, not a network format.
 * Caller retains the original operation, complete request and independently
 * approved response across errors/restarts. Metadata does not authorize traffic.
 */
typedef struct { uint64_t version; uint8_t digest[32]; } qpc_policy_checkpoint_v1;
typedef struct {
    uint8_t operation[32], journal[32], original_owner[32];
    uint8_t original_credential[32], current_credential[32];
    qpc_roster_checkpoint_v1 current_roster;
    qpc_policy_checkpoint_v1 original_policy, previous_policy;
    uint8_t previous_authorization[32];
    uint32_t has_previous_authorization, reserved;
} qpc_policy_renewal_scope_v1;
/* Exactly length valid public bytes, 1..8192. Every unused byte is zero. */
typedef struct { uint32_t length; uint8_t bytes[8192]; } qpc_public_record_v1;
typedef struct {
    qpc_policy_renewal_scope_v1 scope;
    uint8_t account[32];
    qpc_roster_checkpoint_v1 original_roster_checkpoint;
    qpc_public_record_v1 original_credential, original_roster;
    qpc_public_record_v1 current_credential, current_roster;
} qpc_policy_renewal_request_v1;
/* phase0 Absent: all remaining fields zero.
 * phase1 Pending / phase2 Committed: operation, statement and target set;
 * reason, observed_roster and observed_at zero. Pending is not proof of no commit.
 * phase3 AbandonedUncommitted: all IDs/checkpoints/time set; reason1=Expired,
 * reason2=RosterAdvanced. Only exact unchanged predecessor evidence permits this.
 * All phases are historical facts; no live permission or Device is implied.
 */
typedef struct {
    uint32_t phase, reason;
    uint8_t operation[32], statement[32];
    qpc_policy_checkpoint_v1 target;
    qpc_roster_checkpoint_v1 observed_roster;
    uint64_t observed_at;
} qpc_policy_renewal_status_v1;
/* Request requires signed P0 history, not a live runtime/TLS/private signer.
 * Pending work is refused; for an unknown prior submit, retain and reuse the
 * original request, never request another operation to bypass it.
 * Each output below remains untouched after failure. Admitted failures consume
 * the enrollment owner, possibly after a durable commit; close/resume original.
 * Preflight shape failures and pre-admission cancellation retain ownership.
 */
int32_t qpc_enrollment_v1_policy_renewal_request(uint64_t handle, const uint8_t operation[32],
    qpc_policy_renewal_request_v1 *request, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_policy_renewal_status(uint64_t handle,
    qpc_policy_renewal_status_v1 *status, qpc_error_v1 *error);
/* Select current target via select_continued_policy first. Pins and previous
 * policy are independent expectations, never selected from untrusted approvals.
 * Request signed identities and both approvals are reverified each time;
 * native staging rechecks the original actual journal and retains first bytes.
 */
int32_t qpc_enrollment_v1_stage_policy_renewal(uint64_t handle,
    const qpc_policy_renewal_request_v1 *request, const qpc_account_pin_v1 *original_pin,
    const qpc_account_pin_v1 *current_pin, const uint8_t *approvals, size_t approvals_length,
    const qpc_policy_document_v1 *previous, qpc_policy_renewal_status_v1 *status, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_pending_policy_renewal_approval(uint64_t handle, const uint8_t operation[32],
    qpc_public_record_v1 *record, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_reconcile_policy_renewal(uint64_t handle,
    qpc_policy_renewal_status_v1 *status, qpc_error_v1 *error);
/* Historical exact result, no target runtime selection or Device transfer. */
int32_t qpc_enrollment_v1_resolve_policy_renewal(uint64_t handle, const uint8_t operation[32],
    const uint8_t statement[32], const qpc_policy_document_v1 *target,
    qpc_policy_renewal_status_v1 *status, qpc_error_v1 *error);
/* Current target selection + TLS configuration required. Transfers the same
 * owner to Device on success. Required-witness independent P additionally needs
 * the original configured witness, durable retired enrollment completion and
 * fresh current authority; historical progress alone never grants a Device.
 */
int32_t qpc_enrollment_v1_activate_policy_renewal(uint64_t handle, qpc_error_v1 *error);

/* Independently typed required-witness P lifecycle; never G/T proposal grammar.
 * Staging uses stage_policy_renewal with the independently retained request and
 * two root approvals. The existing selected current policy is required only for
 * prepare/commit/activation. Historical recovery/progress load no runtime or
 * application TLS material. Explicit original witness configuration is mandatory
 * for request/commit/status/close/activation; there is no local fallback.
 * Proposal bytes are canonical QPPWNP01, not an approval or terminal receipt.
 * Keep the COMPLETE proposal across calls. Commands reject substituted expected
 * descriptors before dispatch, including after a known retired terminal.
 * Native status 1=Prepared, 2=Applied, 3=Closed, 4=Acknowledged, 5=Unavailable.
 * Unavailable never proves no-commit. Applied/Closed describes history only.
 * ACK and exact pending cleanup happen only after original durable terminal.
 */
typedef struct { uint8_t bytes[296]; } qpc_independent_policy_proposal_v1;
typedef struct {
    uint32_t present, reserved; /* reserved is zero; absent bytes are all zero */
    qpc_independent_policy_proposal_v1 proposal;
} qpc_independent_policy_preparation_v1;
typedef struct {
    uint32_t phase; /* 0=no retained proposal, 1=Reserved, 2=Applied, 3=Closed */
    uint32_t retired; /* 0/1; meaningful only for Applied/Closed */
    qpc_independent_policy_proposal_v1 proposal;
    qpc_policy_checkpoint_v1 target;
} qpc_independent_policy_progress_v1;
/* phase/present zero is LOCAL absence only; staged policy may still exist.
 * Ordinary pointer, cancellation, unknown-outcome and owner rules still apply.
 * Outputs remain untouched on every nonzero return; reopen original owner.
 */
int32_t qpc_enrollment_v1_witnessed_policy_renewal_request(uint64_t handle, const uint8_t operation[32],
    qpc_policy_renewal_request_v1 *request, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_prepare_witnessed_policy_renewal(uint64_t handle,
    const qpc_policy_document_v1 *previous, qpc_independent_policy_proposal_v1 *proposal, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_recover_witnessed_policy_renewal_preparation(uint64_t handle,
    qpc_independent_policy_preparation_v1 *preparation, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_witnessed_policy_renewal_progress(uint64_t handle,
    qpc_independent_policy_progress_v1 *progress, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_commit_witnessed_policy_renewal(uint64_t handle,
    const qpc_independent_policy_proposal_v1 *proposal, uint32_t *observed, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_reconcile_witnessed_policy_renewal(uint64_t handle,
    const qpc_independent_policy_proposal_v1 *proposal, uint32_t *observed, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_close_witnessed_policy_renewal(uint64_t handle,
    const qpc_independent_policy_proposal_v1 *proposal, uint32_t *observed, qpc_error_v1 *error);


/* The original P0 files remain at the enrollment path. Select once per resumed
 * enrollment owner using independently provisioned SDK policy storage at sdk_path
 * (sdk.redb, sdk-policy, sdk-signature, sdk-root) and the explicit target document.
 * No protocol-policy/pin files from sdk_path are consulted. The complete target
 * PolicyStore/runtime is retained until close or transferred to the Device.
 * Selection alone writes no renewal and grants no session permission. Calling
 * selection again conflicts. Admitted failures consume the enrollment resource
 * as with existing mutations; close and explicitly resume the original owner.
 * After every resume, select current policy again before new current work.
 * Historical witnessed close/reconcile and retained preparation need no selection. */
int32_t qpc_enrollment_v1_select_continued_policy(uint64_t handle,
    const uint8_t *sdk_path, size_t sdk_path_length,
    const qpc_policy_document_v1 *target, qpc_error_v1 *error);
/* previous is independently pinned historical P0 or the last adopted policy.
 * previous_t is NULL exactly for P0, otherwise points to the retained32-byte T.
 * Journal/original owner/credential are checked against the original enrollment
 * and verified G. The native coordinator compares exact predecessor state. */
int32_t qpc_enrollment_v1_stage_policy_continuation(uint64_t handle,
    const uint8_t *grant, size_t grant_length, const qpc_account_pin_v1 *pin,
    const uint8_t operation[32], const uint8_t *approvals, size_t approvals_length,
    const qpc_policy_document_v1 *previous, const uint8_t *previous_t,
    qpc_credential_renewal_status_v1 *status, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_stage_continued_credential_renewal(uint64_t handle,
    const uint8_t *grant, size_t grant_length, const qpc_account_pin_v1 *pin,
    const uint8_t operation[32], qpc_credential_renewal_status_v1 *status,
    qpc_error_v1 *error);
/* Length is exactly296/329 for proposals and248/281 for cancellations. The
 * unused tail is zero. These are public coordination metadata, never approvals
 * or terminal receipts. Existing fixed296/248 ABI types remain unchanged. */

/* Original atomic R coordination. The target must be an independently pinned
 * current root roster retaining this exact original credential. Native state
 * derives the actual previous roster and current P authorization; callers cannot
 * replace either with a guessed checkpoint. R is not G or P proposal grammar.
 * Policy choice is explicit: ORIGINAL uses only configured P0, SELECTED uses the
 * already selected independent current P. Neither selection falls back on error.
 * Live policy/identity/runtime are required for prepare and commit; historical
 * recover/progress/close/reconcile/abandonment do not load a current runtime.
 */
enum { QPC_ROSTER_POLICY_ORIGINAL=0, QPC_ROSTER_POLICY_SELECTED=1 };
typedef struct { uint8_t bytes[417]; } qpc_roster_refresh_proposal_v1;
typedef struct {
    uint8_t operation[32];
    qpc_roster_checkpoint_v1 previous, target;
    qpc_policy_checkpoint_v1 policy;
    uint8_t policy_authorization[32];
    uint32_t has_policy_authorization, reserved;
} qpc_roster_refresh_scope_v1;
typedef struct {
    uint32_t present;
    qpc_roster_refresh_proposal_v1 proposal;
    uint8_t reserved[3];
} qpc_roster_refresh_preparation_v1;
typedef struct {
    uint32_t phase; /* 0=Absent, 1=Staged, 2=Reserved, 3=Applied, 4=Closed, 5=AbandonedBeforePreparation */
    uint32_t retired; /* 0/1; meaningful only for Applied/Closed */
    qpc_roster_refresh_scope_v1 scope;
    qpc_roster_refresh_proposal_v1 proposal;
    uint8_t reserved[7];
} qpc_roster_refresh_progress_v1;
typedef struct {
    const uint8_t *certificate; size_t certificate_length;
    const uint8_t *roster; size_t roster_length;
    const qpc_account_pin_v1 *pin;
} qpc_roster_refresh_target_v1;
/* Proposal is canonical QPRWNP01. Retain its COMPLETE 417 bytes across retries.
 * State output: 1=Prepared, 2=Applied, 3=Closed, 4=Acknowledged, 5=Unavailable.
 * Only original durable terminal readback authorizes internal ACK/cleanup.
 * Progress and local preparation absence grant no live owner or no-commit proof.
 * Explicit local abandonment requires no released proposal and actual local
 * pending absence under the original service lease; it is never witness Closed.
 * All reserved bytes are zero. Absent proposal bytes are zero. Pointer, deadline,
 * cancellation and closed-on-admitted-failure rules are the same as other owners.
 */
int32_t qpc_enrollment_v1_prepare_witnessed_roster_refresh(uint64_t handle,
    const uint8_t operation[32], uint32_t policy_source, const qpc_roster_refresh_target_v1 *target,
    qpc_roster_refresh_proposal_v1 *proposal, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_recover_witnessed_roster_refresh_preparation(uint64_t handle,
    qpc_roster_refresh_preparation_v1 *preparation, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_witnessed_roster_refresh_progress(uint64_t handle,
    qpc_roster_refresh_progress_v1 *progress, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_abandon_unprepared_roster_refresh(uint64_t handle,
    const uint8_t operation[32], qpc_roster_refresh_progress_v1 *progress, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_commit_witnessed_roster_refresh(uint64_t handle,
    const qpc_roster_refresh_proposal_v1 *proposal, uint32_t policy_source,
    uint32_t *observed, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_reconcile_witnessed_roster_refresh(uint64_t handle,
    const qpc_roster_refresh_proposal_v1 *proposal, uint32_t *observed, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_close_witnessed_roster_refresh(uint64_t handle,
    const qpc_roster_refresh_proposal_v1 *proposal, uint32_t *observed, qpc_error_v1 *error);

typedef struct { uint32_t length; uint8_t bytes[329]; } qpc_policy_renewal_proposal_v1;
typedef struct { uint32_t length; uint8_t bytes[281]; } qpc_policy_renewal_cancellation_v1;
int32_t qpc_enrollment_v1_prepare_witnessed_policy_continuation(uint64_t handle,
    qpc_policy_renewal_proposal_v1 *proposal, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_prepare_witnessed_policy_cancellation(uint64_t handle,
    qpc_policy_renewal_cancellation_v1 *cancellation, qpc_error_v1 *error);
/* Local-only reconciliation can complete the original authorized transaction;
 * it returns history, never a Device. Required protection is explicitly refused.
 * Witnessed commit first observes original history and loads no current policy
 * for an already terminal operation. New commit requires selected current P1.
 * Existing witnessed close/reconcile functions accept the exact transaction
 * operation/statement for G/T as well, without loading any live target runtime. */
int32_t qpc_enrollment_v1_reconcile_policy_continuation(uint64_t handle,
    qpc_credential_renewal_status_v1 *status, qpc_error_v1 *error);
/* Finish only a matching already-committed LOCAL journal target after P1 expiry.
 * target is independently signature-verified history; no selection, SDK runtime,
 * SDK storage or TLS files are needed. The same handle remains Enrollment.
 * A Pending target without its exact receipt returns SUSPENDED and stays Pending,
 * never ExpiredUncommitted. Required witness recovery uses the existing separate
 * witnessed close/reconcile calls. No new target or operating owner is created. */
int32_t qpc_enrollment_v1_recover_historical_policy_continuation(uint64_t handle,
    const uint8_t operation[32], const uint8_t statement[32],
    const qpc_policy_document_v1 *target,
    qpc_credential_renewal_status_v1 *status, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_commit_witnessed_policy_continuation(uint64_t handle,
    const uint8_t operation[32], const uint8_t statement[32],
    qpc_credential_renewal_status_v1 *status, qpc_error_v1 *error);
/* Converts the same registration handle to a continued Device after native
 * current G/T/roster/runtime admission. Local protection reconciles its original
 * transaction; required protection requires completed ACK and fresh witness
 * admission, never implicit commit. Existing-session child reopen uses immutable
 * P0 and selected P1. Fresh-bootstrap children are refused. Parent close closes
 * the enrolled signer, storage and complete target runtime owner. */
int32_t qpc_enrollment_v1_activate_policy_continuation(uint64_t handle,
    qpc_error_v1 *error);
/* Same-key local renewal uses the original enrollment intent and installed files.
 * Close/join the original device/children, prepare_resume the original intent,
 * stage the independently verified target, then call the same consuming activate.
 * Never replace local-* files or provision to recover this operation.
 * wire is nonempty and at most 65536 bytes. pin is obtained independently of it;
 * operation[32] is retained before submission. The exact configured policy is used.
 * Required-witness renewal must use the witnessed preparation/terminal functions
 * below before activation; staging alone supplies no witness approval.
 * New mutations use enrollment's existing consume-on-admitted-failure rule.
 */
int32_t qpc_enrollment_v1_credential_renewal_status(uint64_t handle,
    qpc_credential_renewal_status_v1 *status, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_stage_credential_renewal(uint64_t handle,
    const uint8_t *wire, size_t wire_length, const qpc_account_pin_v1 *pin,
    const uint8_t operation[32], qpc_credential_renewal_status_v1 *status,
    qpc_error_v1 *error);
/* Resolve original operation/statement; do not reverify an expired target first.
 * Uses the original configured policy and publishes no Device. Exact retained
 * commits win over expiry/revocation. NoCommit requires native monotonic-history
 * proof; missing receipts alone never suffice. The last abandonment is retained
 * until another abandonment or later completion; older outcomes are not invented.
 * Passive renewal_status needs no live policy or TLS configuration.
 */
int32_t qpc_enrollment_v1_reconcile_expired_credential_renewal(uint64_t handle,
    const uint8_t operation[32], const uint8_t statement[32],
    qpc_credential_renewal_status_v1 *status, qpc_error_v1 *error);
/* Canonical QPCRNP01 proposal, exactly 296 public bytes for independent approval.
 * Retrying preparation recovers the original persisted target. It never reseals
 * an existing target, nor treats possession of these bytes as approval.
 */
typedef struct { uint8_t bytes[296]; } qpc_credential_renewal_proposal_v1;
int32_t qpc_enrollment_v1_prepare_witnessed_credential_renewal(uint64_t handle,
    qpc_credential_renewal_proposal_v1 *proposal, qpc_error_v1 *error);
/* Canonical QPCRNC01 target-free expectation, exactly 248 public bytes. Reserve
 * the original staged grant for independent control-plane cancellation; retry
 * retains the same descriptor and head. No target image or current authority is
 * created, and no witness request is sent. Ordinary journal work is suspended
 * while retained. Historical policy suffices, including after runtime expiry.
 * The independent witness must approve Closed before reconciliation can finish;
 * absence/Unavailable is not NoCommit. A full proposal conflicts. After durable
 * Closed, existing reconciliation ACKs and removes only this exact reservation.
 */
typedef struct { uint8_t bytes[248]; } qpc_credential_renewal_cancellation_v1;
int32_t qpc_enrollment_v1_prepare_witnessed_credential_cancellation(uint64_t handle,
    qpc_credential_renewal_cancellation_v1 *cancellation, qpc_error_v1 *error);
/* All operations bind the original enrollment, configured witness and exact
 * operation/statement. They borrow the owner and publish no Device. Commit of a
 * new target requires current valid authority; historical reconciliation and
 * exact terminal cleanup may use an expired, independently pinned signed policy.
 * Close can lose to Applied and then returns Committed. Reconcile sends neither
 * Commit nor Close. Pending/transport failure never proves NoCommit. Only the
 * existing consuming activate releases a Device under fresh operational checks.
 * The same owner cancellation/deadline and admitted-failure rules apply.
 */
int32_t qpc_enrollment_v1_commit_witnessed_credential_renewal(uint64_t handle,
    const uint8_t operation[32], const uint8_t statement[32],
    qpc_credential_renewal_status_v1 *status, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_close_witnessed_credential_renewal(uint64_t handle,
    const uint8_t operation[32], const uint8_t statement[32],
    qpc_credential_renewal_status_v1 *status, qpc_error_v1 *error);
int32_t qpc_enrollment_v1_reconcile_witnessed_credential_renewal(uint64_t handle,
    const uint8_t operation[32], const uint8_t statement[32],
    qpc_credential_renewal_status_v1 *status, qpc_error_v1 *error);
/* Admit a remote grant on the same Device service. It cannot renew the local
 * identity, replace policy, create/reopen a session or update cached Peer views.
 * After success explicitly reopen each original peer/session with its original
 * bundle/pins. Existing peers remain subject to native current-grant checks.
 * Input bounds and independent pin/operation requirements match local staging.
 * On unknown commit, close/reopen original owners and reconcile the same operation;
 * failure is not absence and never authorizes a new journal or new operation ID.
 */
/* Current remote-roster admission through the selected original device parent.
 * The caller supplies authentic public roster bytes (1..65536 bytes) and an
 * independently pinned target checkpoint/root/family. Only known remote accounts
 * with the original authority are accepted; local-account updates use atomic R.
 * Rollback and same-version forks fail; exact retry still requires current local
 * policy/runtime and original witness admission. A returned checkpoint describes
 * the currently installed target, not a transaction receipt or proof of no commit.
 * After I/O/witness/cancel failure, close and reopen the original parent, then
 * reconcile the same target. No output is written on error. No P0 fallback.
 */
int32_t qpc_device_v1_admit_peer_roster(uint64_t handle, const uint8_t *wire,
    size_t wire_length, const qpc_account_pin_v1 *pin,
    qpc_roster_checkpoint_v1 *checkpoint, qpc_error_v1 *error);

int32_t qpc_device_v1_admit_peer_credential_renewal(uint64_t handle,
    const uint8_t *wire, size_t wire_length, const qpc_account_pin_v1 *pin,
    const uint8_t operation[32], qpc_roster_checkpoint_v1 *checkpoint,
    qpc_error_v1 *error);

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
 * the exact report. Metadata retirement requires whole reserved-abandonment ACK
 * or separately settled outcomes for EVERY original committed member, and keeps
 * every original session/bootstrap record and the journal counter. Repeating retirement
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
/* Fresh complete metadata-only reconciliation for a committed batch or an
 * acknowledged abandonment. Requires the original head/witness, including after
 * traffic policy expiry. All member IDs are original and in canonical device
 * order; no caller subset is accepted. Committed or ResolutionPending prevents
 * retirement; DeliveryUnknown never asserts consumption. HistoryRetired cannot
 * distinguish earlier acknowledgement from accounted unknown delivery. Reserved
 * or unacknowledged abandonment returns QPC_SUSPENDED; retired metadata returns
 * QPC_RETIRED. The entire frame is written only on success; unused members and
 * reserved fields are zero. Persist needed results before metadata retirement.
 */
enum {
    QPC_RECONCILED_COMMITTED=1, QPC_RECONCILED_ACKNOWLEDGED=2,
    QPC_RECONCILED_RESOLUTION_PENDING=3, QPC_RECONCILED_DELIVERY_UNKNOWN=4,
    QPC_RECONCILED_HISTORY_RETIRED=5, QPC_RECONCILED_RESERVATION_ABANDONED=6
};
typedef struct {
    uint8_t device[16], session[32], message[32];
    uint32_t state, reserved_zero;
} qpc_account_reconciled_member_v1;
typedef struct {
    uint8_t batch[32];
    uint32_t member_count, reserved_zero;
    qpc_account_reconciled_member_v1 members[32];
} qpc_account_reconciliation_v1;
int32_t qpc_recovery_v1_account_reconciliation(uint64_t handle,
    qpc_account_reconciliation_v1 *result, qpc_error_v1 *error);

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
