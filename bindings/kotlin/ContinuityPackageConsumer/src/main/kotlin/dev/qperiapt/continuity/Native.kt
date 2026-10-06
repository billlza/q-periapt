// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity

import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemoryLayout
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout.ADDRESS
import java.lang.foreign.ValueLayout.JAVA_BYTE
import java.lang.foreign.ValueLayout.JAVA_INT
import java.lang.foreign.ValueLayout.JAVA_LONG
import java.lang.foreign.ValueLayout.JAVA_SHORT
import java.lang.invoke.MethodHandles
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/** Raw handles stay internal to this module and are synthetic at the Java boundary. */
internal object ContinuityNative {
    private fun array(length: Long) = MemoryLayout.sequenceLayout(length, JAVA_BYTE)
    private fun struct(vararg fields: Pair<String, MemoryLayout>): MemoryLayout {
        val members = mutableListOf<MemoryLayout>()
        var size = 0L
        val alignment = fields.maxOf { it.second.byteAlignment() }
        for ((name, layout) in fields) {
            val padding = (layout.byteAlignment() - size % layout.byteAlignment()) % layout.byteAlignment()
            if (padding != 0L) members.add(MemoryLayout.paddingLayout(padding))
            members.add(layout.withName(name))
            size += padding + layout.byteSize()
        }
        val tail = (alignment - size % alignment) % alignment
        if (tail != 0L) members.add(MemoryLayout.paddingLayout(tail))
        return MemoryLayout.structLayout(*members.toTypedArray())
    }
    private val errorLayout = struct("code" to JAVA_INT, "length" to JAVA_INT,
        "truncated" to JAVA_INT, "message" to array(512))
    private val witnessLayout = struct("address" to ADDRESS, "length" to JAVA_LONG, "timeout" to JAVA_INT)
    private val optionsLayout = struct("kind" to JAVA_INT, "quality" to JAVA_INT,
        "carrier" to JAVA_INT, "witness" to ADDRESS)
    private val setupStatusLayout = struct("phase" to JAVA_INT, "journal" to array(32))
    private val setupPreparationLayout = struct("protection" to JAVA_INT, "journal" to array(32),
        "subject" to array(96), "image_digest" to array(32))
    private val enrollmentIntentLayout = struct("root" to ADDRESS, "root_length" to JAVA_LONG,
        "device" to array(16), "generation" to JAVA_LONG, "family" to array(32), "valid_from" to JAVA_LONG, "valid_until" to JAVA_LONG)
    private val checkpointLayout = struct("version" to JAVA_LONG, "digest" to array(32))
    private val enrollmentPinLayout = struct("account" to array(32), "root" to ADDRESS, "root_length" to JAVA_LONG,
        "family" to array(32), "checkpoint" to checkpointLayout)
    private val enrollmentStatusLayout = struct("phase" to JAVA_INT, "signing" to array(32), "journal" to array(32),
        "previous" to checkpointLayout, "next" to checkpointLayout)
    private val enrollmentRequestLayout = struct("length" to JAVA_INT, "bytes" to array(8192))
    private val rosterResolutionLayout = struct("outcome" to JAVA_INT, "reserved" to JAVA_INT,
        "journal" to array(32), "previous" to checkpointLayout, "target" to checkpointLayout,
        "observed" to checkpointLayout, "observed_at" to JAVA_LONG)
    private val credentialRenewalStatusLayout = struct("phase" to JAVA_INT, "operation" to array(32),
        "statement" to array(32), "checkpoint" to checkpointLayout, "observed_at" to JAVA_LONG)
    private val credentialRenewalProposalLayout = struct("bytes" to array(296))
    private val credentialRenewalCancellationLayout = struct("bytes" to array(248))
    private val policyDocumentLayout = struct("root" to ADDRESS, "root_length" to JAVA_LONG,
        "family" to array(32), "version" to JAVA_LONG, "digest" to array(32), "wire" to ADDRESS, "wire_length" to JAVA_LONG)
    private val policyRenewalProposalLayout = struct("length" to JAVA_INT, "bytes" to array(329))
    private val policyRenewalCancellationLayout = struct("length" to JAVA_INT, "bytes" to array(281))
    private val policyRenewalScopeLayout = struct("operation" to array(32), "journal" to array(32),
        "original_owner" to array(32), "original_credential" to array(32), "current_credential" to array(32),
        "current_roster" to checkpointLayout, "original_policy" to checkpointLayout, "previous_policy" to checkpointLayout,
        "previous_authorization" to array(32), "has_previous_authorization" to JAVA_INT, "reserved" to JAVA_INT)
    private val policyRenewalRequestLayout = struct("scope" to policyRenewalScopeLayout, "account" to array(32),
        "original_roster_checkpoint" to checkpointLayout, "original_credential" to enrollmentRequestLayout,
        "original_roster" to enrollmentRequestLayout, "current_credential" to enrollmentRequestLayout, "current_roster" to enrollmentRequestLayout)
    private val policyRenewalStatusLayout = struct("phase" to JAVA_INT, "reason" to JAVA_INT,
        "operation" to array(32), "statement" to array(32), "target" to checkpointLayout,
        "observed_roster" to checkpointLayout, "observed_at" to JAVA_LONG)
    private val independentPolicyProposalLayout = struct("bytes" to array(296))
    private val independentPolicyPreparationLayout = struct("present" to JAVA_INT, "reserved" to JAVA_INT,
        "proposal" to independentPolicyProposalLayout)
    private val independentPolicyProgressLayout = struct("phase" to JAVA_INT, "retired" to JAVA_INT,
        "proposal" to independentPolicyProposalLayout, "target" to checkpointLayout)
    private val servedLayout = struct("kind" to JAVA_INT, "session" to array(32),
        "message" to array(32), "duplicate" to JAVA_INT)
    private val headerLayout = struct("peer_generation" to JAVA_LONG, "confirmed_epoch" to JAVA_LONG,
        "sending_epoch" to JAVA_LONG, "receiving_epoch" to JAVA_LONG, "pending_epoch" to JAVA_LONG,
        "has_pending_epoch" to JAVA_INT, "role" to JAVA_INT, "reserved_count" to JAVA_INT,
        "epoch_count" to JAVA_INT, "session" to array(32), "context" to array(32),
        "report" to array(32), "peer_account" to array(32), "peer_device" to array(16))
    private val epochLayout = struct("epoch" to JAVA_LONG, "acknowledged_before" to JAVA_LONG,
        "sent" to JAVA_LONG, "consumed_before" to JAVA_LONG, "received" to JAVA_LONG,
        "peer_sent" to JAVA_LONG, "has_peer_sent" to JAVA_INT, "resolution" to JAVA_INT,
        "unconfirmed_count" to JAVA_INT, "delivery_count" to JAVA_INT, "skipped_count" to JAVA_INT,
        "reserved_zero" to JAVA_INT, "resolution_report" to array(32))
    private val reservedLayout = struct("plaintext_bytes" to JAVA_LONG, "associated_data_bytes" to JAVA_LONG,
        "message" to array(32))
    private val unconfirmedLayout = struct("message" to array(32), "ciphertext_digest" to array(32))
    private val deliveryLayout = struct("index" to JAVA_LONG, "plaintext_bytes" to JAVA_LONG, "message" to array(32))
    private val statusLayout = struct("phase" to JAVA_INT, "report" to array(32))
    private val accountTargetLayout = struct("peer" to JAVA_LONG, "session" to array(32))
    private val accountDeliveryLayout = struct("device" to array(16), "session" to array(32),
        "message" to array(32), "outcome" to JAVA_INT, "exchanges" to JAVA_INT)
    private val accountCleanupHeaderLayout = struct("batch" to array(32), "report" to array(32),
        "member_count" to JAVA_INT, "reserved_zero" to JAVA_INT)
    private val accountCleanupMemberLayout = struct("generation" to JAVA_LONG, "confirmed_epoch" to JAVA_LONG,
        "sending_epoch" to JAVA_LONG, "receiving_epoch" to JAVA_LONG, "pending_epoch" to JAVA_LONG,
        "has_pending_epoch" to JAVA_INT, "role" to JAVA_INT, "epoch_count" to JAVA_INT,
        "reserved_zero" to JAVA_INT, "device" to array(16), "context" to array(32), "session" to array(32))
    private val accountReconciledMemberLayout = struct("device" to array(16), "session" to array(32),
        "message" to array(32), "state" to JAVA_INT, "reserved_zero" to JAVA_INT)
    private val accountReconciliationLayout = struct("batch" to array(32), "member_count" to JAVA_INT,
        "reserved_zero" to JAVA_INT, "members" to MemoryLayout.sequenceLayout(32, accountReconciledMemberLayout))

    private val linker = Linker.nativeLinker().also {
        require(ADDRESS.byteSize() == 8L && it.canonicalLayouts().getValue("size_t").withoutName() == JAVA_LONG) {
            "qpc-owner/1 JVM binding requires a 64-bit C size_t ABI"
        }
    }
    private val lookup = run {
        val selected = System.getProperty("qperiapt.continuity.lib")
            ?: error("qperiapt.continuity.lib must select the installed qpc-owner/1 library")
        val path = Path.of(selected)
        require(path.isAbsolute && Files.isRegularFile(path)) { "Continuity library must be an absolute regular file" }
        SymbolLookup.libraryLookup(path, Arena.global())
    }
    private fun function(name: String, vararg parameters: MemoryLayout) =
        linker.downcallHandle(lookup.findOrThrow(name), FunctionDescriptor.of(JAVA_INT, *parameters))
    private val prepare = function("qpc_owner_v1_prepare_open", ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS)
    private val prepareReopen = function("qpc_owner_v1_prepare_reopen", ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS)
    private val prepareCreateSetup = function("qpc_setup_v1_prepare_create", ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS)
    private val prepareResumeSetup = function("qpc_setup_v1_prepare_resume", ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS)
    private val prepareCreateEnrollment = function("qpc_enrollment_v1_prepare_create", ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS)
    private val prepareResumeEnrollment = function("qpc_enrollment_v1_prepare_resume", ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS)
    private val preparePeer = function("qpc_peer_v1_prepare", JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS)
    private val preparePeerReopen = function("qpc_peer_v1_prepare_reopen", JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, ADDRESS)
    private val calls = mapOf(
        "witnessed_policy_renewal_request" to function("qpc_enrollment_v1_witnessed_policy_renewal_request", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "prepare_witnessed_policy_renewal" to function("qpc_enrollment_v1_prepare_witnessed_policy_renewal", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "recover_witnessed_policy_renewal_preparation" to function("qpc_enrollment_v1_recover_witnessed_policy_renewal_preparation", JAVA_LONG, ADDRESS, ADDRESS),
        "witnessed_policy_renewal_progress" to function("qpc_enrollment_v1_witnessed_policy_renewal_progress", JAVA_LONG, ADDRESS, ADDRESS),
        "commit_witnessed_policy_renewal" to function("qpc_enrollment_v1_commit_witnessed_policy_renewal", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "reconcile_witnessed_policy_renewal" to function("qpc_enrollment_v1_reconcile_witnessed_policy_renewal", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "close_witnessed_policy_renewal" to function("qpc_enrollment_v1_close_witnessed_policy_renewal", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "policy_renewal_request" to function("qpc_enrollment_v1_policy_renewal_request", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "policy_renewal_status" to function("qpc_enrollment_v1_policy_renewal_status", JAVA_LONG, ADDRESS, ADDRESS),
        "stage_policy_renewal" to function("qpc_enrollment_v1_stage_policy_renewal", JAVA_LONG,
            ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "pending_policy_renewal_approval" to function("qpc_enrollment_v1_pending_policy_renewal_approval", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "reconcile_policy_renewal" to function("qpc_enrollment_v1_reconcile_policy_renewal", JAVA_LONG, ADDRESS, ADDRESS),
        "resolve_policy_renewal" to function("qpc_enrollment_v1_resolve_policy_renewal", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "activate_policy_renewal" to function("qpc_enrollment_v1_activate_policy_renewal", JAVA_LONG, ADDRESS),
        "select_continued_policy" to function("qpc_enrollment_v1_select_continued_policy", JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS),
        "stage_policy_continuation" to function("qpc_enrollment_v1_stage_policy_continuation", JAVA_LONG, ADDRESS, JAVA_LONG,
            ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "stage_continued_credential_renewal" to function("qpc_enrollment_v1_stage_continued_credential_renewal", JAVA_LONG,
            ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "prepare_witnessed_policy_continuation" to function("qpc_enrollment_v1_prepare_witnessed_policy_continuation", JAVA_LONG, ADDRESS, ADDRESS),
        "prepare_witnessed_policy_cancellation" to function("qpc_enrollment_v1_prepare_witnessed_policy_cancellation", JAVA_LONG, ADDRESS, ADDRESS),
        "reconcile_policy_continuation" to function("qpc_enrollment_v1_reconcile_policy_continuation", JAVA_LONG, ADDRESS, ADDRESS),
        "commit_witnessed_policy_continuation" to function("qpc_enrollment_v1_commit_witnessed_policy_continuation", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "recover_historical_policy_continuation" to function("qpc_enrollment_v1_recover_historical_policy_continuation", JAVA_LONG,
            ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "activate_policy_continuation" to function("qpc_enrollment_v1_activate_policy_continuation", JAVA_LONG, ADDRESS),
        "enrollment_key" to function("qpc_enrollment_v1_provision_wrapping_key", ADDRESS, JAVA_LONG, ADDRESS),
        "enrollment_status" to function("qpc_enrollment_v1_status", JAVA_LONG, ADDRESS, ADDRESS),
        "enrollment_request" to function("qpc_enrollment_v1_request", JAVA_LONG, ADDRESS, ADDRESS),
        "enrollment_accept" to function("qpc_enrollment_v1_accept", JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "enrollment_storage" to function("qpc_enrollment_v1_prepare_storage", JAVA_LONG, ADDRESS, ADDRESS),
        "enrollment_refresh" to function("qpc_enrollment_v1_refresh_roster", JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "resolve_roster_refresh" to function("qpc_enrollment_v1_resolve_roster_refresh", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "enrollment_activate" to function("qpc_enrollment_v1_activate", JAVA_LONG, ADDRESS),
        "credential_renewal_status" to function("qpc_enrollment_v1_credential_renewal_status", JAVA_LONG, ADDRESS, ADDRESS),
        "stage_credential_renewal" to function("qpc_enrollment_v1_stage_credential_renewal", JAVA_LONG, ADDRESS, JAVA_LONG,
            ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "reconcile_expired_credential_renewal" to function("qpc_enrollment_v1_reconcile_expired_credential_renewal",
            JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "prepare_witnessed_credential_renewal" to function("qpc_enrollment_v1_prepare_witnessed_credential_renewal",
            JAVA_LONG, ADDRESS, ADDRESS),
        "prepare_witnessed_credential_cancellation" to function("qpc_enrollment_v1_prepare_witnessed_credential_cancellation",
            JAVA_LONG, ADDRESS, ADDRESS),
        "commit_witnessed_credential_renewal" to function("qpc_enrollment_v1_commit_witnessed_credential_renewal",
            JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "close_witnessed_credential_renewal" to function("qpc_enrollment_v1_close_witnessed_credential_renewal",
            JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "reconcile_witnessed_credential_renewal" to function("qpc_enrollment_v1_reconcile_witnessed_credential_renewal",
            JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "admit_peer_credential_renewal" to function("qpc_device_v1_admit_peer_credential_renewal", JAVA_LONG, ADDRESS,
            JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "setup_status" to function("qpc_setup_v1_status", JAVA_LONG, ADDRESS, ADDRESS),
        "setup_storage" to function("qpc_setup_v1_prepare_storage", JAVA_LONG, ADDRESS, ADDRESS),
        "setup_activate" to function("qpc_setup_v1_activate", JAVA_LONG, ADDRESS),
        "next_account" to function("qpc_device_v1_next_account", JAVA_LONG, ADDRESS, ADDRESS),
        "account_status" to function("qpc_device_v1_account_status", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "send_account_member" to function("qpc_device_v1_send_account_member", JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_LONG,
            ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS),
        "finish_open" to function("qpc_owner_v1_finish_open", JAVA_LONG, ADDRESS),
        "cancel" to function("qpc_owner_v1_cancel", JAVA_LONG, ADDRESS),
        "close" to function("qpc_owner_v1_close", JAVA_LONG, ADDRESS),
        "establish" to function("qpc_owner_v1_establish", JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "next_message" to function("qpc_owner_v1_next_message", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "send" to function("qpc_owner_v1_send", JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS,
            ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "message_status" to function("qpc_owner_v1_message_status", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "rekey" to function("qpc_owner_v1_rekey", JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS),
        "listen" to function("qpc_owner_v1_listen", JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS),
        "serve" to function("qpc_owner_v1_serve", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, ADDRESS),
        "serve_rekey" to function("qpc_owner_v1_serve_rekey", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "session_count" to function("qpc_recovery_v1_session_count", JAVA_LONG, ADDRESS, ADDRESS),
        "session_at" to function("qpc_recovery_v1_session_at", JAVA_LONG, JAVA_INT, ADDRESS, ADDRESS),
        "select" to function("qpc_recovery_v1_select", JAVA_LONG, ADDRESS, ADDRESS),
        "select_archive" to function("qpc_recovery_v1_select_archive", JAVA_LONG, ADDRESS, JAVA_LONG, ADDRESS),
        "archive" to function("qpc_recovery_v1_archive", JAVA_LONG, ADDRESS, ADDRESS),
        "begin" to function("qpc_recovery_v1_begin", JAVA_LONG, ADDRESS, ADDRESS),
        "status" to function("qpc_recovery_v1_status", JAVA_LONG, ADDRESS, ADDRESS),
        "reserved" to function("qpc_recovery_v1_reserved", JAVA_LONG, JAVA_INT, ADDRESS, ADDRESS),
        "epoch" to function("qpc_recovery_v1_epoch", JAVA_LONG, JAVA_INT, ADDRESS, ADDRESS),
        "unconfirmed" to function("qpc_recovery_v1_unconfirmed", JAVA_LONG, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS),
        "delivery" to function("qpc_recovery_v1_delivery", JAVA_LONG, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS),
        "skipped" to function("qpc_recovery_v1_skipped", JAVA_LONG, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS),
        "acknowledge" to function("qpc_recovery_v1_acknowledge", JAVA_LONG, ADDRESS, ADDRESS),
        "retire" to function("qpc_recovery_v1_retire", JAVA_LONG, ADDRESS, ADDRESS, ADDRESS),
        "restore_index" to function("qpc_recovery_v1_restore_index", JAVA_LONG, ADDRESS),
        "select_account" to function("qpc_recovery_v1_select_account", JAVA_LONG, ADDRESS, ADDRESS),
        "account_begin" to function("qpc_recovery_v1_account_begin", JAVA_LONG, ADDRESS, ADDRESS),
        "account_cleanup_status" to function("qpc_recovery_v1_account_status", JAVA_LONG, ADDRESS, ADDRESS),
        "account_reconciliation" to function("qpc_recovery_v1_account_reconciliation", JAVA_LONG, ADDRESS, ADDRESS),
        "account_member" to function("qpc_recovery_v1_account_member", JAVA_LONG, JAVA_INT, ADDRESS, ADDRESS),
        "account_reserved" to function("qpc_recovery_v1_account_reserved", JAVA_LONG, JAVA_INT, ADDRESS, ADDRESS),
        "account_epoch" to function("qpc_recovery_v1_account_epoch", JAVA_LONG, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS),
        "account_unconfirmed" to function("qpc_recovery_v1_account_unconfirmed", JAVA_LONG, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS),
        "account_delivery" to function("qpc_recovery_v1_account_delivery", JAVA_LONG, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS),
        "account_skipped" to function("qpc_recovery_v1_account_skipped", JAVA_LONG, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS),
        "account_acknowledge" to function("qpc_recovery_v1_account_acknowledge", JAVA_LONG, ADDRESS, ADDRESS),
        "account_retire" to function("qpc_recovery_v1_account_retire", JAVA_LONG, ADDRESS),
    )
    private fun offset(layout: MemoryLayout, name: String) = layout.byteOffset(MemoryLayout.PathElement.groupElement(name))
    private fun malformed(message: String): Nothing = throw ContinuityBoundaryFailure(message)
    private fun checked(operation: String, code: Int, error: MemorySegment): ContinuityFailure? {
        val length = error.get(JAVA_INT, offset(errorLayout, "length"))
        val truncated = error.get(JAVA_INT, offset(errorLayout, "truncated"))
        if (error.get(JAVA_INT, 0) != code || length !in 0..512 || truncated !in 0..1 ||
            (code == 0 && (length != 0 || truncated != 0)) || (code != 0 && length == 0)) {
            malformed("$operation returned an inconsistent native error record")
        }
        if (code == 0) return null
        val bytes = error.asSlice(offset(errorLayout, "message"), length.toLong()).toArray(JAVA_BYTE)
        val text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        return ContinuityFailure(operation, code, text, truncated == 1)
    }
    private fun invoke(arena: Arena, operation: String, vararg args: Any) {
        val error = arena.allocate(errorLayout)
        val code = calls.getValue(operation).invokeWithArguments(args.toList() + error) as Int
        checked(operation, code, error)?.let { throw it }
    }
    private fun Arena.bytes(value: ByteArray): MemorySegment = allocate(value.size.toLong().coerceAtLeast(1)).also {
        if (value.isNotEmpty()) it.asSlice(0, value.size.toLong()).copyFrom(MemorySegment.ofArray(value))
    }
    private fun text(value: String, maximum: Int): ByteArray {
        require(value.isNotEmpty() && value.length <= maximum && !value.contains('\u0000')) { "invalid Continuity text" }
        val encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value))
        require(encoded.remaining() <= maximum) { "Continuity UTF-8 input exceeds its byte bound" }
        return ByteArray(encoded.remaining()).also { encoded.get(it) }
    }
    private fun index(value: Long): Int {
        require(value in 0..0xffff_ffffL) { "index must fit an unsigned 32-bit value" }
        return value.toInt()
    }
    private fun flag(value: Int): Boolean = when (value) {
        0 -> false
        1 -> true
        else -> malformed("native presence flag differs")
    }
    private fun uint(value: Int): Long = java.lang.Integer.toUnsignedLong(value)
    private fun exchanges(value: Short): Int = java.lang.Short.toUnsignedInt(value).also {
        if (it !in 1..8) malformed("native exchange count differs")
    }
    @JvmSynthetic internal fun prepare(path: String, kind: Int, quality: Int, carrier: WitnessCarrier,
                                       session: SessionID? = null, setup: SetupIntent? = null,
                                       enrollment: EnrollmentPreparation? = null): Long {
        require(setup == null || session == null) { "setup cannot select a session" }
        require(enrollment == null || (session == null && setup == null && kind == 3 && quality == 0)) {
            "registration requires its own original device preparation"
        }
        val encoded = text(path, 4096)
        return Arena.ofConfined().use { arena ->
            val options = arena.allocate(optionsLayout)
            options.set(JAVA_INT, offset(optionsLayout, "kind"), kind)
            options.set(JAVA_INT, offset(optionsLayout, "quality"), quality)
            val witness = when (carrier) {
                WitnessCarrier.Local -> MemorySegment.NULL
                else -> {
                    val address: String
                    val timeout: Int
                    val selected: Int
                    when (carrier) {
                        is WitnessCarrier.SignedTCP -> { address = carrier.address; timeout = carrier.timeoutMilliseconds; selected = 1 }
                        is WitnessCarrier.MutualTLS -> { address = carrier.address; timeout = carrier.timeoutMilliseconds; selected = 2 }
                        WitnessCarrier.Local -> error("local carrier handled above")
                    }
                    val endpoint = text(address, 128)
                    options.set(JAVA_INT, offset(optionsLayout, "carrier"), selected)
                    arena.allocate(witnessLayout).also {
                        it.set(ADDRESS, offset(witnessLayout, "address"), arena.bytes(endpoint))
                        it.set(JAVA_LONG, offset(witnessLayout, "length"), endpoint.size.toLong())
                        it.set(JAVA_INT, offset(witnessLayout, "timeout"), timeout)
                    }
                }
            }
            options.set(ADDRESS, offset(optionsLayout, "witness"), witness)
            val output = arena.allocate(JAVA_LONG)
            val error = arena.allocate(errorLayout)
            val operation = if (enrollment != null) {
                if (enrollment.action == SetupIntent.CREATE) "enrollment_prepare_create" else "enrollment_prepare_resume"
            } else when (setup) {
                SetupIntent.CREATE -> "setup_prepare_create"
                SetupIntent.RESUME -> "setup_prepare_resume"
                null -> if (session == null) "prepare_open" else "prepare_reopen"
            }
            val code = if (enrollment != null) {
                val intent = encodeEnrollmentIntent(arena, enrollment.intent)
                val selected = if (enrollment.action == SetupIntent.CREATE) prepareCreateEnrollment else prepareResumeEnrollment
                selected.invokeWithArguments(arena.bytes(encoded), encoded.size.toLong(), intent, options, output, error) as Int
            } else if (setup != null) {
                val selected = if (setup == SetupIntent.CREATE) prepareCreateSetup else prepareResumeSetup
                selected.invokeWithArguments(arena.bytes(encoded), encoded.size.toLong(), options, output, error) as Int
            } else if (session == null) {
                prepare.invokeWithArguments(arena.bytes(encoded), encoded.size.toLong(), options, output, error) as Int
            } else {
                prepareReopen.invokeWithArguments(arena.bytes(encoded), encoded.size.toLong(), options,
                    arena.bytes(session.encoded()), output, error) as Int
            }
            checked(operation, code, error)?.let { throw it }
            output.get(JAVA_LONG, 0).also { if (it == 0L) malformed("native preparation returned a zero handle") }
        }
    }
    @JvmSynthetic internal fun simple(handle: Long, operation: String) = Arena.ofConfined().use { invoke(it, operation, handle) }
    @JvmSynthetic internal fun decodeSetupStatus(phase: Int, journal: ByteArray): InstallationStatus {
        if (journal.size != 32 || journal.all { it == 0.toByte() }) malformed("native installation journal differs")
        val selected = when (phase) {
            1 -> InstallationPhase.CREATING
            2 -> InstallationPhase.ACTIVE
            else -> malformed("native installation phase differs")
        }
        return InstallationStatus(selected, JournalID(journal))
    }
    @JvmSynthetic internal fun decodeSetupPreparation(protection: Int, journal: ByteArray,
                                                     subject: ByteArray, digest: ByteArray): InstallationPreparation {
        if (journal.size != 32 || journal.all { it == 0.toByte() } || subject.size != 96 || digest.size != 32) {
            malformed("native installation genesis shape differs")
        }
        val id = JournalID(journal)
        return when (protection) {
            1 -> {
                if (subject.any { it != 0.toByte() } || digest.any { it != 0.toByte() }) malformed("local installation has witness metadata")
                InstallationPreparation.Local(id)
            }
            2 -> {
                if (!subject.copyOfRange(0, 32).contentEquals(journal) ||
                    subject.sliceArray(32..63).all { it == 0.toByte() } || subject.sliceArray(64..95).all { it == 0.toByte() } ||
                    digest.all { it == 0.toByte() }) malformed("native witnessed installation genesis differs")
                InstallationPreparation.RequiresEnrollment(WitnessGenesis(id, PublicBytes(subject), PublicBytes(digest)))
            }
            else -> malformed("native installation protection differs")
        }
    }
    @JvmSynthetic internal fun setupStatus(handle: Long): InstallationStatus = record(handle, "setup_status", setupStatusLayout) {
        decodeSetupStatus(it.integer("phase"), it.bytes("journal", 32))
    }
    @JvmSynthetic internal fun setupStorage(handle: Long): InstallationPreparation = record(handle, "setup_storage", setupPreparationLayout) {
        decodeSetupPreparation(it.integer("protection"), it.bytes("journal", 32), it.bytes("subject", 96), it.bytes("image_digest", 32))
    }
    private fun MemorySegment.put(layout: MemoryLayout, field: String, value: ByteArray) {
        asSlice(offset(layout, field), value.size.toLong()).copyFrom(MemorySegment.ofArray(value))
    }
    private fun encodeEnrollmentIntent(arena: Arena, intent: EnrollmentIntent): MemorySegment =
        arena.allocate(enrollmentIntentLayout).also { output ->
            val root = intent.root.encoded()
            output.set(ADDRESS, offset(enrollmentIntentLayout, "root"), arena.bytes(root))
            output.set(JAVA_LONG, offset(enrollmentIntentLayout, "root_length"), root.size.toLong())
            output.put(enrollmentIntentLayout, "device", intent.device.encoded())
            output.set(JAVA_LONG, offset(enrollmentIntentLayout, "generation"), intent.generation.bits())
            output.put(enrollmentIntentLayout, "family", intent.family.encoded())
            output.set(JAVA_LONG, offset(enrollmentIntentLayout, "valid_from"), intent.validFrom.bits())
            output.set(JAVA_LONG, offset(enrollmentIntentLayout, "valid_until"), intent.validUntil.bits())
        }
    private fun encodeCheckpoint(arena: Arena, checkpoint: RosterCheckpoint): MemorySegment = arena.allocate(checkpointLayout).also {
        it.set(JAVA_LONG, offset(checkpointLayout, "version"), checkpoint.version.bits())
        it.put(checkpointLayout, "digest", checkpoint.digest.encoded())
    }
    private fun encodeAccountPin(arena: Arena, pin: AccountPin): MemorySegment = arena.allocate(enrollmentPinLayout).also {
        val root = pin.root.encoded()
        it.put(enrollmentPinLayout, "account", pin.account.encoded())
        it.set(ADDRESS, offset(enrollmentPinLayout, "root"), arena.bytes(root))
        it.set(JAVA_LONG, offset(enrollmentPinLayout, "root_length"), root.size.toLong())
        it.put(enrollmentPinLayout, "family", pin.family.encoded())
        it.asSlice(offset(enrollmentPinLayout, "checkpoint"), checkpointLayout.byteSize()).copyFrom(encodeCheckpoint(arena, pin.checkpoint))
    }
    @JvmSynthetic internal fun enrollmentKey(path: String) {
        val encoded = text(path, 4096)
        Arena.ofConfined().use { invoke(it, "enrollment_key", it.bytes(encoded), encoded.size.toLong()) }
    }
    @JvmSynthetic internal fun decodeEnrollmentStatus(phase: Int, signing: ByteArray, journal: ByteArray,
                                                      previous: ByteArray, next: ByteArray): EnrollmentStatus {
        if (signing.size != 32 || signing.all { it == 0.toByte() } || journal.size != 32
            || previous.size != 40 || next.size != 40) malformed("native enrollment status width or signing ID differs")
        val selected = when (phase) {
            1 -> EnrollmentPhase.PREPARING
            2 -> EnrollmentPhase.REQUESTED
            3 -> EnrollmentPhase.ACCEPTED
            4 -> EnrollmentPhase.ACTIVATING
            5 -> EnrollmentPhase.ACTIVE
            6 -> EnrollmentPhase.REFRESHING
            7 -> EnrollmentPhase.ROSTER_RESOLVED
            else -> malformed("native enrollment phase differs")
        }
        val hasJournal = journal.any { it != 0.toByte() }
        if (hasJournal != (phase >= 3)) malformed("native enrollment journal presence differs")
        val transition = if (phase == 6 || phase == 7) {
            fun checkpoint(bytes: ByteArray): RosterCheckpoint {
                val version = Counter64.fromBits(ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()).long)
                val digest = bytes.copyOfRange(8, 40)
                if (version == Counter64.ZERO || version.bits() == -1L || digest.all { it == 0.toByte() }) {
                    malformed("native enrollment checkpoint differs")
                }
                return RosterCheckpoint(version, digest)
            }
            val before = checkpoint(previous); val after = checkpoint(next)
            if (before.version >= after.version) malformed("native enrollment refresh is not increasing")
            RosterTransition(before, after)
        } else {
            if (previous.any { it != 0.toByte() } || next.any { it != 0.toByte() }) malformed("unexpected native roster transition")
            null
        }
        return EnrollmentStatus(selected, SigningKeyID(signing), if (hasJournal) JournalID(journal) else null, transition)
    }
    private fun decodeEnrollmentStatus(fields: Fields): EnrollmentStatus = decodeEnrollmentStatus(
        fields.integer("phase"), fields.bytes("signing", 32), fields.bytes("journal", 32),
        fields.bytes("previous", 40), fields.bytes("next", 40))
    @JvmSynthetic internal fun enrollmentStatus(handle: Long): EnrollmentStatus =
        record(handle, "enrollment_status", enrollmentStatusLayout, decode = ::decodeEnrollmentStatus)
    @JvmSynthetic internal fun decodeEnrollmentRequest(length: Int, bytes: ByteArray): PublicBytes {
        if (bytes.size != 8192 || length !in 1..8192 || bytes.drop(length).any { it != 0.toByte() }) {
            malformed("native enrollment request length or unused tail differs")
        }
        return PublicBytes(bytes.copyOfRange(0, length))
    }
    @JvmSynthetic internal fun enrollmentRequest(handle: Long): PublicBytes = record(handle, "enrollment_request", enrollmentRequestLayout) {
        decodeEnrollmentRequest(it.integer("length"), it.bytes("bytes", 8192))
    }
    @JvmSynthetic internal fun enrollmentAccept(handle: Long, certificate: ByteArray, roster: ByteArray, pin: AccountPin): JournalID {
        require(certificate.size in 1..8192 && roster.size in 1..8192) { "invalid enrollment response length" }
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(32)
            invoke(arena, "enrollment_accept", handle, arena.bytes(certificate), certificate.size.toLong(),
                   arena.bytes(roster), roster.size.toLong(), encodeAccountPin(arena, pin), output)
            val journal = output.toArray(JAVA_BYTE)
            if (journal.all { it == 0.toByte() }) malformed("native enrollment accepted a zero journal")
            JournalID(journal)
        }
    }
    @JvmSynthetic internal fun enrollmentStorage(handle: Long): InstallationPreparation = record(handle, "enrollment_storage", setupPreparationLayout) {
        decodeSetupPreparation(it.integer("protection"), it.bytes("journal", 32), it.bytes("subject", 96), it.bytes("image_digest", 32))
    }
    @JvmSynthetic internal fun enrollmentRefresh(handle: Long, previous: RosterCheckpoint, roster: ByteArray, pin: AccountPin): EnrollmentStatus {
        require(roster.size in 1..8192) { "invalid enrollment roster length" }
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(enrollmentStatusLayout)
            invoke(arena, "enrollment_refresh", handle, encodeCheckpoint(arena, previous), arena.bytes(roster),
                   roster.size.toLong(), encodeAccountPin(arena, pin), output)
            decodeEnrollmentStatus(Fields(output, enrollmentStatusLayout))
        }
    }
    @JvmSynthetic internal fun decodeRosterRefreshResolution(outcome: Int, reserved: Int, journal: ByteArray,
        previous: ByteArray, target: ByteArray, observed: ByteArray, observedAt: Counter64): RosterRefreshResolution {
        if (reserved != 0 || journal.size != 32 || journal.all { it == 0.toByte() } || observedAt == Counter64.ZERO) {
            malformed("native roster resolution header differs")
        }
        val selected = when (outcome) {
            1 -> RosterRefreshOutcome.COMMITTED
            2 -> RosterRefreshOutcome.EXPIRED_UNCOMMITTED
            3 -> RosterRefreshOutcome.SUPERSEDED_UNCOMMITTED
            4 -> RosterRefreshOutcome.SUPERSEDED_UNKNOWN
            else -> malformed("native roster resolution outcome differs")
        }
        val before = decodeRosterCheckpoint(previous)
        val next = decodeRosterCheckpoint(target)
        val actual = decodeRosterCheckpoint(observed)
        if (before.version >= next.version || actual.version < before.version ||
            (actual.version == before.version && actual != before)) malformed("native roster resolution order differs")
        val valid = when (selected) {
            RosterRefreshOutcome.COMMITTED -> actual == next
            RosterRefreshOutcome.EXPIRED_UNCOMMITTED -> actual.version < next.version
            RosterRefreshOutcome.SUPERSEDED_UNCOMMITTED -> actual.version == next.version && actual != next
            RosterRefreshOutcome.SUPERSEDED_UNKNOWN -> actual.version > next.version
        }
        if (!valid) malformed("native roster resolution contradicts its observed head")
        return RosterRefreshResolution(selected, JournalID(journal), before, next, actual, observedAt)
    }
    @JvmSynthetic internal fun resolveRosterRefresh(handle: Long, previous: RosterCheckpoint,
        target: RosterCheckpoint): RosterRefreshResolution = Arena.ofConfined().use { arena ->
        val output = arena.allocate(rosterResolutionLayout)
        invoke(arena, "resolve_roster_refresh", handle, encodeCheckpoint(arena, previous), encodeCheckpoint(arena, target), output)
        val fields = Fields(output, rosterResolutionLayout)
        decodeRosterRefreshResolution(fields.integer("outcome"), fields.integer("reserved"),
            fields.bytes("journal", 32), fields.bytes("previous", 40), fields.bytes("target", 40),
            fields.bytes("observed", 40), fields.counter("observed_at"))
    }
    private fun decodeRosterCheckpoint(bytes: ByteArray): RosterCheckpoint {
        if (bytes.size != 40) malformed("native roster checkpoint width differs")
        val version = Counter64.fromBits(ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()).long)
        val digest = bytes.copyOfRange(8, 40)
        if (version == Counter64.ZERO || version.bits() == -1L || digest.all { it == 0.toByte() }) {
            malformed("native roster checkpoint differs")
        }
        return RosterCheckpoint(version, digest)
    }
    @JvmSynthetic internal fun decodeCredentialRenewalStatus(phase: Int, operation: ByteArray, statement: ByteArray,
                                                            checkpoint: ByteArray, observedAt: Counter64): CredentialRenewalStatus {
        if (operation.size != 32 || statement.size != 32 || checkpoint.size != 40) {
            malformed("native credential renewal status width differs")
        }
        if (phase !in 0..4) malformed("native credential renewal phase differs")
        if (phase == 0) {
            if (operation.any { it != 0.toByte() } || statement.any { it != 0.toByte() } ||
                checkpoint.any { it != 0.toByte() } || observedAt != Counter64.ZERO) {
                malformed("absent native credential renewal has retained fields")
            }
            return CredentialRenewalStatus.Absent
        }
        if (operation.all { it == 0.toByte() } || statement.all { it == 0.toByte() }) {
            malformed("native credential renewal is missing its original operation or statement")
        }
        if ((phase == 3) != (observedAt != Counter64.ZERO)) malformed("native renewal observation time differs")
        val id = CredentialRenewalID(operation)
        val signed = CredentialRenewalStatementID(statement)
        if (phase == 1) {
            if (checkpoint.any { it != 0.toByte() }) malformed("pending native renewal has a checkpoint")
            return CredentialRenewalStatus.Pending(id, signed)
        }
        val head = decodeRosterCheckpoint(checkpoint)
        return when (phase) {
            2 -> CredentialRenewalStatus.Committed(id, signed, head)
            3 -> CredentialRenewalStatus.ExpiredUncommitted(id, signed, head, observedAt)
            else -> CredentialRenewalStatus.Closed(id, signed, head)
        }
    }
    private fun decodeCredentialRenewalStatus(fields: Fields): CredentialRenewalStatus = decodeCredentialRenewalStatus(
        fields.integer("phase"), fields.bytes("operation", 32), fields.bytes("statement", 32),
        fields.bytes("checkpoint", 40), fields.counter("observed_at"))
    @JvmSynthetic internal fun credentialRenewalStatus(handle: Long): CredentialRenewalStatus =
        record(handle, "credential_renewal_status", credentialRenewalStatusLayout, decode = ::decodeCredentialRenewalStatus)
    @JvmSynthetic internal fun stageCredentialRenewal(handle: Long, wire: ByteArray, pin: AccountPin,
                                                      operation: CredentialRenewalID): CredentialRenewalStatus {
        require(wire.size in 1..65536) { "credential renewal grant must contain 1..65536 bytes" }
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(credentialRenewalStatusLayout)
            invoke(arena, "stage_credential_renewal", handle, arena.bytes(wire), wire.size.toLong(),
                encodeAccountPin(arena, pin), arena.bytes(operation.encoded()), output)
            decodeCredentialRenewalStatus(Fields(output, credentialRenewalStatusLayout))
        }
    }
    @JvmSynthetic internal fun reconcileExpiredCredentialRenewal(handle: Long, operation: CredentialRenewalID,
                                                                 statement: CredentialRenewalStatementID): CredentialRenewalStatus =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(credentialRenewalStatusLayout)
            invoke(arena, "reconcile_expired_credential_renewal", handle, arena.bytes(operation.encoded()),
                arena.bytes(statement.encoded()), output)
            decodeCredentialRenewalStatus(Fields(output, credentialRenewalStatusLayout))
        }
    @JvmSynthetic internal fun prepareWitnessedCredentialRenewal(handle: Long): CredentialRenewalProposal =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(credentialRenewalProposalLayout)
            invoke(arena, "prepare_witnessed_credential_renewal", handle, output)
            CredentialRenewalProposal.decode(output.toArray(JAVA_BYTE))
        }
    @JvmSynthetic internal fun prepareWitnessedCredentialCancellation(handle: Long): CredentialRenewalCancellation =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(credentialRenewalCancellationLayout)
            invoke(arena, "prepare_witnessed_credential_cancellation", handle, output)
            CredentialRenewalCancellation.decode(output.toArray(JAVA_BYTE))
        }
    internal enum class WitnessRenewalAction(val function: String) {
        COMMIT("commit_witnessed_credential_renewal"), CLOSE("close_witnessed_credential_renewal"),
        RECONCILE("reconcile_witnessed_credential_renewal"),
    }
    @JvmSynthetic internal fun witnessedCredentialRenewal(handle: Long, operation: CredentialRenewalID,
                                                          statement: CredentialRenewalStatementID,
                                                          action: WitnessRenewalAction): CredentialRenewalStatus =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(credentialRenewalStatusLayout)
            invoke(arena, action.function, handle, arena.bytes(operation.encoded()), arena.bytes(statement.encoded()), output)
            decodeCredentialRenewalStatus(Fields(output, credentialRenewalStatusLayout))
        }
    private fun encodePolicyDocument(arena: Arena, document: PolicyDocument): MemorySegment =
        arena.allocate(policyDocumentLayout).also { output ->
            val root = document.root.encoded(); val wire = document.wire.encoded()
            output.set(ADDRESS, offset(policyDocumentLayout, "root"), arena.bytes(root))
            output.set(JAVA_LONG, offset(policyDocumentLayout, "root_length"), root.size.toLong())
            output.put(policyDocumentLayout, "family", document.family.encoded())
            output.set(JAVA_LONG, offset(policyDocumentLayout, "version"), document.checkpoint.version.bits())
            output.put(policyDocumentLayout, "digest", document.checkpoint.digest.encoded())
            output.set(ADDRESS, offset(policyDocumentLayout, "wire"), arena.bytes(wire))
            output.set(JAVA_LONG, offset(policyDocumentLayout, "wire_length"), wire.size.toLong())
        }
    @JvmSynthetic internal fun selectContinuedPolicy(handle: Long, path: String, document: PolicyDocument) {
        val encoded = text(path, 4096)
        Arena.ofConfined().use { arena ->
            invoke(arena, "select_continued_policy", handle, arena.bytes(encoded), encoded.size.toLong(), encodePolicyDocument(arena, document))
        }
    }
    @JvmSynthetic internal fun policyRenewalRequest(handle: Long, operation: PolicyRenewalID, witnessed: Boolean = false): PolicyRenewalRequest =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(policyRenewalRequestLayout)
            invoke(arena, if (witnessed) "witnessed_policy_renewal_request" else "policy_renewal_request", handle, arena.bytes(operation.encoded()), output)
            PolicyRenewalCodec.decodeRequest(output.toArray(JAVA_BYTE))
        }
    @JvmSynthetic internal fun prepareWitnessedPolicyRenewal(handle: Long, previous: PolicyDocument): IndependentPolicyProposal =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(independentPolicyProposalLayout)
            invoke(arena, "prepare_witnessed_policy_renewal", handle, encodePolicyDocument(arena, previous), output)
            IndependentPolicyCodec.proposal(output.toArray(JAVA_BYTE))
        }
    @JvmSynthetic internal fun recoverWitnessedPolicyRenewalPreparation(handle: Long): IndependentPolicyProposal? =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(independentPolicyPreparationLayout)
            invoke(arena, "recover_witnessed_policy_renewal_preparation", handle, output)
            IndependentPolicyCodec.preparation(output.toArray(JAVA_BYTE))
        }
    @JvmSynthetic internal fun witnessedPolicyRenewalProgress(handle: Long): IndependentPolicyProgress =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(independentPolicyProgressLayout)
            invoke(arena, "witnessed_policy_renewal_progress", handle, output)
            IndependentPolicyCodec.progress(output.toArray(JAVA_BYTE))
        }
    @JvmSynthetic internal fun independentPolicyCommand(handle: Long, proposal: IndependentPolicyProposal, command: String): IndependentPolicyState =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(JAVA_INT)
            val input = arena.allocate(independentPolicyProposalLayout)
            input.copyFrom(MemorySegment.ofArray(proposal.encoded()))
            invoke(arena, command, handle, input, output)
            IndependentPolicyCodec.state(output.get(JAVA_INT, 0))
        }
    @JvmSynthetic internal fun policyRenewalStatus(handle: Long, reconcile: Boolean = false): PolicyRenewalStatus =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(policyRenewalStatusLayout)
            invoke(arena, if (reconcile) "reconcile_policy_renewal" else "policy_renewal_status", handle, output)
            PolicyRenewalCodec.decodeStatus(output.toArray(JAVA_BYTE))
        }
    @JvmSynthetic internal fun stagePolicyRenewal(handle: Long, request: PolicyRenewalRequest,
        originalPin: AccountPin, currentPin: AccountPin, approvals: ByteArray, previous: PolicyDocument): PolicyRenewalStatus {
        require(approvals.size == 7618) { "independent policy approvals must contain 7618 bytes" }
        return Arena.ofConfined().use { arena ->
            val input = arena.allocate(policyRenewalRequestLayout)
            input.copyFrom(MemorySegment.ofArray(PolicyRenewalCodec.encodeRequest(request)))
            val output = arena.allocate(policyRenewalStatusLayout)
            invoke(arena, "stage_policy_renewal", handle, input, encodeAccountPin(arena, originalPin), encodeAccountPin(arena, currentPin),
                arena.bytes(approvals), approvals.size.toLong(), encodePolicyDocument(arena, previous), output)
            PolicyRenewalCodec.decodeStatus(output.toArray(JAVA_BYTE))
        }
    }
    @JvmSynthetic internal fun pendingPolicyRenewalApproval(handle: Long, operation: PolicyRenewalID): PublicBytes =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(enrollmentRequestLayout)
            invoke(arena, "pending_policy_renewal_approval", handle, arena.bytes(operation.encoded()), output)
            val bytes = PolicyRenewalCodec.decodePublicRecord(output.toArray(JAVA_BYTE))
            if (bytes.size != 7618) malformed("pending independent policy approval width differs")
            PublicBytes(bytes)
        }
    @JvmSynthetic internal fun resolvePolicyRenewal(handle: Long, operation: PolicyRenewalID,
        statement: PolicyRenewalStatementID, target: PolicyDocument): PolicyRenewalStatus = Arena.ofConfined().use { arena ->
        val output = arena.allocate(policyRenewalStatusLayout)
        invoke(arena, "resolve_policy_renewal", handle, arena.bytes(operation.encoded()), arena.bytes(statement.encoded()), encodePolicyDocument(arena, target), output)
        PolicyRenewalCodec.decodeStatus(output.toArray(JAVA_BYTE))
    }
    @JvmSynthetic internal fun stagePolicyContinuation(handle: Long, wire: ByteArray, pin: AccountPin,
        operation: CredentialRenewalID, approvals: ByteArray, previous: PolicyDocument,
        previousT: PolicyContinuationStatementID?): CredentialRenewalStatus {
        require(wire.size in 1..65536) { "credential renewal grant must contain 1..65536 bytes" }
        // QPPCTB01: two independent envelopes over the exact 490-byte statement.
        require(approvals.size in 1..7746) { "policy approvals must contain 1..7746 bytes" }
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(credentialRenewalStatusLayout)
            invoke(arena, "stage_policy_continuation", handle, arena.bytes(wire), wire.size.toLong(), encodeAccountPin(arena, pin),
                arena.bytes(operation.encoded()), arena.bytes(approvals), approvals.size.toLong(), encodePolicyDocument(arena, previous),
                previousT?.let { arena.bytes(it.encoded()) } ?: MemorySegment.NULL, output)
            decodeCredentialRenewalStatus(Fields(output, credentialRenewalStatusLayout))
        }
    }
    @JvmSynthetic internal fun stageContinuedCredentialRenewal(handle: Long, wire: ByteArray, pin: AccountPin,
        operation: CredentialRenewalID): CredentialRenewalStatus {
        require(wire.size in 1..65536) { "credential renewal grant must contain 1..65536 bytes" }
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(credentialRenewalStatusLayout)
            invoke(arena, "stage_continued_credential_renewal", handle, arena.bytes(wire), wire.size.toLong(),
                encodeAccountPin(arena, pin), arena.bytes(operation.encoded()), output)
            decodeCredentialRenewalStatus(Fields(output, credentialRenewalStatusLayout))
        }
    }
    private fun policyRecord(bytes: ByteArray, layout: MemoryLayout, capacity: Int): Pair<Int, ByteArray> {
        if (bytes.size.toLong() != layout.byteSize()) malformed("native policy metadata record width differs")
        val at = offset(layout, "bytes").toInt()
        val length = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()).getInt(offset(layout, "length").toInt())
        // Only the declared byte array has a zero-tail contract. C struct
        // alignment padding after it is not serialized protocol data.
        return length to bytes.copyOfRange(at, at + capacity)
    }
    @JvmSynthetic internal fun decodePolicyProposalRecord(bytes: ByteArray): PolicyRenewalProposal {
        val (length, storage) = policyRecord(bytes, policyRenewalProposalLayout, 329)
        return PolicyRenewalProposal.decode(length, storage)
    }
    @JvmSynthetic internal fun decodePolicyCancellationRecord(bytes: ByteArray): PolicyRenewalCancellation {
        val (length, storage) = policyRecord(bytes, policyRenewalCancellationLayout, 281)
        return PolicyRenewalCancellation.decode(length, storage)
    }
    @JvmSynthetic internal fun prepareWitnessedPolicyContinuation(handle: Long): PolicyRenewalProposal =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(policyRenewalProposalLayout)
            invoke(arena, "prepare_witnessed_policy_continuation", handle, output)
            decodePolicyProposalRecord(output.toArray(JAVA_BYTE))
        }
    @JvmSynthetic internal fun prepareWitnessedPolicyCancellation(handle: Long): PolicyRenewalCancellation =
        Arena.ofConfined().use { arena ->
            val output = arena.allocate(policyRenewalCancellationLayout)
            invoke(arena, "prepare_witnessed_policy_cancellation", handle, output)
            decodePolicyCancellationRecord(output.toArray(JAVA_BYTE))
        }
    @JvmSynthetic internal fun reconcilePolicyContinuation(handle: Long): CredentialRenewalStatus =
        record(handle, "reconcile_policy_continuation", credentialRenewalStatusLayout, decode = ::decodeCredentialRenewalStatus)
    @JvmSynthetic internal fun commitWitnessedPolicyContinuation(handle: Long, operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID): CredentialRenewalStatus = Arena.ofConfined().use { arena ->
            val output = arena.allocate(credentialRenewalStatusLayout)
            invoke(arena, "commit_witnessed_policy_continuation", handle, arena.bytes(operation.encoded()), arena.bytes(statement.encoded()), output)
            decodeCredentialRenewalStatus(Fields(output, credentialRenewalStatusLayout))
        }
    @JvmSynthetic internal fun recoverHistoricalPolicyContinuation(handle: Long, operation: CredentialRenewalID,
        statement: CredentialRenewalStatementID, target: PolicyDocument): CredentialRenewalStatus = Arena.ofConfined().use { arena ->
            val output = arena.allocate(credentialRenewalStatusLayout)
            invoke(arena, "recover_historical_policy_continuation", handle, arena.bytes(operation.encoded()), arena.bytes(statement.encoded()),
                encodePolicyDocument(arena, target), output)
            decodeCredentialRenewalStatus(Fields(output, credentialRenewalStatusLayout))
        }
    @JvmSynthetic internal fun admitPeerCredentialRenewal(handle: Long, wire: ByteArray, pin: AccountPin,
                                                          operation: CredentialRenewalID): RosterCheckpoint {
        require(wire.size in 1..65536) { "credential renewal grant must contain 1..65536 bytes" }
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(checkpointLayout)
            invoke(arena, "admit_peer_credential_renewal", handle, arena.bytes(wire), wire.size.toLong(),
                encodeAccountPin(arena, pin), arena.bytes(operation.encoded()), output)
            decodeRosterCheckpoint(output.toArray(JAVA_BYTE))
        }
    }
    @JvmSynthetic internal fun preparePeer(parent: Long, path: String, quality: PrekeyQuality,
                                           role: BootstrapRole, session: SessionID?): Long {
        val encoded = text(path, 4096)
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(JAVA_LONG)
            val error = arena.allocate(errorLayout)
            val args = listOf(parent, arena.bytes(encoded), encoded.size.toLong(), quality.code, role.code)
            val code = if (session == null) {
                preparePeer.invokeWithArguments(args + listOf(output, error)) as Int
            } else {
                preparePeerReopen.invokeWithArguments(args + listOf(arena.bytes(session.encoded()), output, error)) as Int
            }
            checked(if (session == null) "prepare_peer" else "prepare_peer_reopen", code, error)?.let { throw it }
            output.get(JAVA_LONG, 0).also { if (it == 0L) malformed("native peer preparation returned a zero handle") }
        }
    }
    @JvmSynthetic internal fun nextAccount(handle: Long): AccountOperationID = Arena.ofConfined().use { arena ->
        val output = arena.allocate(32)
        invoke(arena, "next_account", handle, output)
        val bytes = output.toArray(JAVA_BYTE)
        if (bytes.all { it == 0.toByte() }) malformed("native account operation is zero")
        AccountOperationID(bytes)
    }
    @JvmSynthetic internal fun decodeAccountStatus(state: Int, report: ByteArray): AccountStatus {
        if (report.size != 32) malformed("native account report length differs")
        val hasReport = report.any { it != 0.toByte() }
        return when (state) {
            0, 1, 2, 5 -> {
                if (hasReport) malformed("native account status has an unexpected report")
                when (state) {
                    0 -> AccountStatus.Absent
                    1 -> AccountStatus.Reserved
                    2 -> AccountStatus.Committed
                    else -> AccountStatus.Retired
                }
            }
            3, 4 -> {
                if (!hasReport) malformed("native account status is missing its report")
                val id = AccountAbandonmentID(report)
                if (state == 3) AccountStatus.Abandoning(id) else AccountStatus.Abandoned(id)
            }
            else -> malformed("native account status differs")
        }
    }
    @JvmSynthetic internal fun accountStatus(handle: Long, operation: AccountOperationID): AccountStatus = Arena.ofConfined().use { arena ->
        val status = arena.allocate(JAVA_BYTE)
        val report = arena.allocate(32)
        invoke(arena, "account_status", handle, arena.bytes(operation.encoded()), status, report)
        decodeAccountStatus(status.get(JAVA_BYTE, 0).toInt(), report.toArray(JAVA_BYTE))
    }
    @JvmSynthetic internal fun decodeAccountDelivery(device: ByteArray, session: ByteArray, message: ByteArray,
                                                     outcome: Int, count: Int, selected: SessionID): AccountDelivery {
        if (device.size != 16 || device.all { it == 0.toByte() } || !session.contentEquals(selected.encoded()) ||
            message.size != 32 || message.all { it == 0.toByte() } || count !in 0..8) {
            malformed("native account delivery shape differs")
        }
        val result = when (outcome) {
            1 -> AccountDeliveryOutcome.Consumed(Consumption.CONFIRMED)
            2 -> {
                if (count == 0) malformed("pending prefix has no exchange")
                AccountDeliveryOutcome.Consumed(Consumption.PREFIX_PENDING)
            }
            3 -> AccountDeliveryOutcome.ResolutionPending
            4 -> AccountDeliveryOutcome.DeliveryUnknown
            5 -> AccountDeliveryOutcome.HistoryRetired
            6 -> AccountDeliveryOutcome.ReservationAbandoned
            else -> malformed("native account delivery outcome differs")
        }
        return AccountDelivery(PublicBytes(device), SessionID(session), MessageID(message), result, count)
    }
    @JvmSynthetic internal fun sendAccountMember(handle: Long, operation: AccountOperationID, account: AccountID,
                                                  targets: List<Pair<Long, SessionID>>, selected: Int, peer: String,
                                                  plaintext: ByteArray, associatedData: ByteArray): AccountDelivery {
        require(targets.size in 1..32 && selected in targets.indices) { "invalid account target count or selection" }
        require(plaintext.size <= 16384 && associatedData.size <= 1024) { "Continuity message input exceeds its byte bound" }
        val address = text(peer, 128)
        return Arena.ofConfined().use { arena ->
            val records = arena.allocate(MemoryLayout.sequenceLayout(targets.size.toLong(), accountTargetLayout))
            for ((index, target) in targets.withIndex()) {
                val record = records.asSlice(index * accountTargetLayout.byteSize(), accountTargetLayout)
                record.set(JAVA_LONG, offset(accountTargetLayout, "peer"), target.first)
                record.asSlice(offset(accountTargetLayout, "session"), 32).copyFrom(MemorySegment.ofArray(target.second.encoded()))
            }
            val payload = arena.bytes(plaintext)
            val ad = arena.bytes(associatedData)
            try {
                val output = arena.allocate(accountDeliveryLayout)
                invoke(arena, "send_account_member", handle, records, targets.size.toLong(), selected.toLong(),
                    arena.bytes(operation.encoded()), arena.bytes(account.encoded()), arena.bytes(address), address.size.toLong(),
                    payload, plaintext.size.toLong(), ad, associatedData.size.toLong(), output)
                fun bytes(name: String, size: Long) = output.asSlice(offset(accountDeliveryLayout, name), size).toArray(JAVA_BYTE)
                decodeAccountDelivery(bytes("device", 16), bytes("session", 32), bytes("message", 32),
                    output.get(JAVA_INT, offset(accountDeliveryLayout, "outcome")),
                    output.get(JAVA_INT, offset(accountDeliveryLayout, "exchanges")), targets[selected].second)
            } finally { payload.fill(0); ad.fill(0) }
        }
    }
    @JvmSynthetic internal fun establish(handle: Long, peer: String, request: InitiationID): Establishment {
        val address = text(peer, 128)
        return Arena.ofConfined().use { arena ->
            val session = arena.allocate(32)
            val count = arena.allocate(JAVA_SHORT)
            invoke(arena, "establish", handle, arena.bytes(address), address.size.toLong(), arena.bytes(request.encoded()), session, count)
            Establishment(SessionID(session.toArray(JAVA_BYTE)), exchanges(count.get(JAVA_SHORT, 0)))
        }
    }
    @JvmSynthetic internal fun next(handle: Long, session: SessionID): MessageID = Arena.ofConfined().use { arena ->
        val output = arena.allocate(32)
        invoke(arena, "next_message", handle, arena.bytes(session.encoded()), output)
        MessageID(output.toArray(JAVA_BYTE))
    }
    @JvmSynthetic internal fun messageStatus(handle: Long, session: SessionID, message: MessageID): MessageStatus = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_BYTE)
        invoke(arena, "message_status", handle, arena.bytes(session.encoded()), arena.bytes(message.encoded()), output)
        MessageStatus.entries.singleOrNull { it.code == output.get(JAVA_BYTE, 0).toInt() }
            ?: malformed("native message status differs")
    }
    @JvmSynthetic internal fun send(handle: Long, peer: String, session: SessionID, message: MessageID,
        plaintext: ByteArray, associatedData: ByteArray): SendResult {
        val address = text(peer, 128)
        require(plaintext.size <= 16384 && associatedData.size <= 1024) { "Continuity message input exceeds its byte bound" }
        return Arena.ofConfined().use { arena ->
            val payload = arena.bytes(plaintext)
            val ad = arena.bytes(associatedData)
            try {
                val consumption = arena.allocate(JAVA_BYTE)
                val count = arena.allocate(JAVA_SHORT)
                invoke(arena, "send", handle, arena.bytes(address), address.size.toLong(), arena.bytes(session.encoded()),
                    arena.bytes(message.encoded()), payload, plaintext.size.toLong(), ad, associatedData.size.toLong(), consumption, count)
                val state = Consumption.entries.singleOrNull { it.code == consumption.get(JAVA_BYTE, 0).toInt() }
                    ?: malformed("native consumption differs")
                SendResult(state, exchanges(count.get(JAVA_SHORT, 0)))
            } finally { payload.fill(0); ad.fill(0) }
        }
    }
    @JvmSynthetic internal fun rekey(handle: Long, peer: String, session: SessionID, target: Counter64): Counter64 {
        val address = text(peer, 128)
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(JAVA_LONG)
            invoke(arena, "rekey", handle, arena.bytes(address), address.size.toLong(), arena.bytes(session.encoded()), target.bits(), output)
            Counter64.fromBits(output.get(JAVA_LONG, 0)).also { if (it != target) malformed("native rekey target differs") }
        }
    }
    @JvmSynthetic internal fun listen(handle: Long, address: String): Int {
        val bytes = text(address, 128)
        return Arena.ofConfined().use { arena ->
            val output = arena.allocate(JAVA_SHORT)
            invoke(arena, "listen", handle, arena.bytes(bytes), bytes.size.toLong(), output)
            java.lang.Short.toUnsignedInt(output.get(JAVA_SHORT, 0)).also { if (it == 0) malformed("native listener port is zero") }
        }
    }
    @JvmSynthetic internal fun serveRekey(handle: Long, session: SessionID): Counter64 = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_LONG)
        invoke(arena, "serve_rekey", handle, arena.bytes(session.encoded()), output)
        Counter64.fromBits(output.get(JAVA_LONG, 0))
    }

    private class CommitInvocation(private val commit: ApplicationCommit) {
        var failure: Throwable? = null
            private set
        var count: Int = 0
            private set
        fun invoke(context: MemorySegment, session: MemorySegment, message: MemorySegment,
            plaintext: MemorySegment, length: Long): Int = try {
            count += 1
            if (count != 1 || context.address() != 0L || session.address() == 0L || message.address() == 0L ||
                length !in 0..16384 || (length != 0L && plaintext.address() == 0L)) {
                throw ContinuityBoundaryFailure("invalid native application callback")
            }
            val bytes = if (length == 0L) byteArrayOf() else plaintext.reinterpret(length).toArray(JAVA_BYTE)
            commit.commit(ApplicationDelivery(SessionID(session.toArray(JAVA_BYTE)), MessageID(message.toArray(JAVA_BYTE)), bytes))
            0
        } catch (error: Throwable) {
            // No JVM exception may unwind through a native upcall. The original
            // cause is returned to this exact serve invocation after C returns.
            failure = error
            if (error is ApplicationCommitRefusal) error.status else 1
        }
    }
    private val commitDescriptor = FunctionDescriptor.of(JAVA_INT, ADDRESS,
        ADDRESS.withTargetLayout(array(32)), ADDRESS.withTargetLayout(array(32)), ADDRESS, JAVA_LONG)
    private val commitMethod = MethodHandles.lookup().findVirtual(CommitInvocation::class.java,
        "invoke", commitDescriptor.toMethodType())
    @JvmSynthetic internal fun serve(handle: Long, commit: ApplicationCommit): Served = Arena.ofConfined().use { arena ->
        val invocation = CommitInvocation(commit)
        val stub = linker.upcallStub(commitMethod.bindTo(invocation), commitDescriptor, arena)
        val output = arena.allocate(servedLayout)
        val error = arena.allocate(errorLayout)
        val code = calls.getValue("serve").invokeWithArguments(handle, stub, MemorySegment.NULL, output, error) as Int
        val nativeFailure = checked("serve", code, error)
        val cause = invocation.failure
        if (cause != null) {
            if (nativeFailure == null) malformed("native serve accepted a failed callback")
            throw ContinuityCallbackFailure(nativeFailure, cause)
        }
        if (nativeFailure != null) throw nativeFailure
        val session = SessionID(output.asSlice(offset(servedLayout, "session"), 32).toArray(JAVA_BYTE))
        val message = output.asSlice(offset(servedLayout, "message"), 32).toArray(JAVA_BYTE)
        val duplicate = flag(output.get(JAVA_INT, offset(servedLayout, "duplicate")))
        when (output.get(JAVA_INT, offset(servedLayout, "kind"))) {
            1 -> {
                if (duplicate || message.any { it != 0.toByte() } || invocation.count != 0) malformed("native bootstrap result differs")
                Served.Bootstrap(session)
            }
            2 -> {
                if (invocation.count != if (duplicate) 0 else 1) malformed("native message callback count differs")
                Served.Message(session, MessageID(message), duplicate)
            }
            else -> malformed("native served kind differs")
        }
    }

    private class Fields(private val bytes: MemorySegment, private val layout: MemoryLayout) {
        fun integer(name: String): Int = bytes.get(JAVA_INT, offset(layout, name))
        fun counter(name: String): Counter64 = Counter64.fromBits(bytes.get(JAVA_LONG, offset(layout, name)))
        fun bytes(name: String, length: Long): ByteArray = bytes.asSlice(offset(layout, name), length).toArray(JAVA_BYTE)
        fun optional(flagName: String, valueName: String): Counter64? {
            val present = flag(integer(flagName))
            val value = counter(valueName)
            if (!present && value != Counter64.ZERO) malformed("absent native counter is nonzero")
            return if (present) value else null
        }
    }
    private fun <T> record(handle: Long, operation: String, layout: MemoryLayout,
        indices: List<Int> = emptyList(), decode: (Fields) -> T): T = Arena.ofConfined().use { arena ->
        val output = arena.allocate(layout)
        val arguments = arrayListOf<Any>(handle)
        arguments.addAll(indices)
        arguments.add(output)
        invoke(arena, operation, *arguments.toTypedArray())
        decode(Fields(output, layout))
    }
    @JvmSynthetic internal fun sessionCount(handle: Long): Long = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_INT)
        invoke(arena, "session_count", handle, output)
        uint(output.get(JAVA_INT, 0))
    }
    @JvmSynthetic internal fun sessionAt(handle: Long, at: Long): SessionID = Arena.ofConfined().use { arena ->
        val selected = index(at)
        val output = arena.allocate(32)
        invoke(arena, "session_at", handle, selected, output)
        SessionID(output.toArray(JAVA_BYTE))
    }
    @JvmSynthetic internal fun idOperation(handle: Long, operation: String, id: ContinuityID) = Arena.ofConfined().use {
        invoke(it, operation, handle, it.bytes(id.encoded()))
    }
    @JvmSynthetic internal fun selectArchive(handle: Long, archive: ByteArray) {
        require(archive.size == 362) { "a closure archive contains exactly 362 bytes" }
        Arena.ofConfined().use { invoke(it, "select_archive", handle, it.bytes(archive), archive.size.toLong()) }
    }
    @JvmSynthetic internal fun archive(handle: Long): ByteArray = Arena.ofConfined().use { arena ->
        val output = arena.allocate(362)
        invoke(arena, "archive", handle, output)
        output.toArray(JAVA_BYTE)
    }
    @JvmSynthetic internal fun begin(handle: Long): ClosureHeader = record(handle, "begin", headerLayout) { fields ->
        val role = SessionRole.entries.singleOrNull { it.code == fields.integer("role") } ?: malformed("native session role differs")
        ClosureHeader(fields.counter("peer_generation"), fields.counter("confirmed_epoch"), fields.counter("sending_epoch"),
            fields.counter("receiving_epoch"), fields.optional("has_pending_epoch", "pending_epoch"), role,
            uint(fields.integer("reserved_count")), uint(fields.integer("epoch_count")), SessionID(fields.bytes("session", 32)),
            PublicBytes(fields.bytes("context", 32)), ClosureReportID(fields.bytes("report", 32)),
            PublicBytes(fields.bytes("peer_account", 32)), PublicBytes(fields.bytes("peer_device", 16)))
    }
    @JvmSynthetic internal fun status(handle: Long): ClosureStatus = record(handle, "status", statusLayout) { fields ->
        val report = fields.bytes("report", 32)
        when (fields.integer("phase")) {
            0 -> {
                if (report.any { it != 0.toByte() }) malformed("open closure returned a report")
                ClosureStatus.Open
            }
            1 -> ClosureStatus.Pending(ClosureReportID(report))
            2 -> ClosureStatus.Closed(ClosureReportID(report))
            else -> malformed("native closure phase differs")
        }
    }
    @JvmSynthetic internal fun reservation(handle: Long, at: Long): ReservedLoss = record(handle, "reserved", reservedLayout, listOf(index(at))) {
        ReservedLoss(MessageID(it.bytes("message", 32)), it.counter("plaintext_bytes"), it.counter("associated_data_bytes"))
    }
    private fun decodeEpoch(fields: Fields): ClosureEpoch {
        if (fields.integer("reserved_zero") != 0) malformed("native epoch reserved field differs")
        val bytes = fields.bytes("resolution_report", 32)
        val resolution = when (fields.integer("resolution")) {
            0 -> {
                if (bytes.any { it != 0.toByte() }) malformed("unrequested resolution returned a report")
                EpochResolution.Unrequested
            }
            1 -> EpochResolution.Pending(ClosureReportID(bytes))
            2 -> EpochResolution.Acknowledged(ClosureReportID(bytes))
            else -> malformed("native epoch resolution differs")
        }
        return ClosureEpoch(fields.counter("epoch"), fields.counter("acknowledged_before"), fields.counter("sent"),
            fields.counter("consumed_before"), fields.counter("received"), fields.optional("has_peer_sent", "peer_sent"),
            resolution, uint(fields.integer("unconfirmed_count")), uint(fields.integer("delivery_count")), uint(fields.integer("skipped_count")))
    }
    @JvmSynthetic internal fun epoch(handle: Long, at: Long): ClosureEpoch =
        record(handle, "epoch", epochLayout, listOf(index(at)), ::decodeEpoch)
    @JvmSynthetic internal fun unconfirmed(handle: Long, epoch: Long, at: Long): UnconfirmedLoss =
        record(handle, "unconfirmed", unconfirmedLayout, listOf(index(epoch), index(at))) {
            UnconfirmedLoss(MessageID(it.bytes("message", 32)), PublicBytes(it.bytes("ciphertext_digest", 32)))
        }
    @JvmSynthetic internal fun delivery(handle: Long, epoch: Long, at: Long): DeliveryLoss =
        record(handle, "delivery", deliveryLayout, listOf(index(epoch), index(at))) {
            DeliveryLoss(MessageID(it.bytes("message", 32)), it.counter("index"), it.counter("plaintext_bytes"))
        }
    @JvmSynthetic internal fun skipped(handle: Long, epoch: Long, at: Long): Counter64 = Arena.ofConfined().use { arena ->
        val selectedEpoch = index(epoch)
        val selectedIndex = index(at)
        val output = arena.allocate(JAVA_LONG)
        invoke(arena, "skipped", handle, selectedEpoch, selectedIndex, output)
        Counter64.fromBits(output.get(JAVA_LONG, 0))
    }
    @JvmSynthetic internal fun retire(handle: Long, report: ClosureReportID): Boolean = Arena.ofConfined().use { arena ->
        val output = arena.allocate(JAVA_BYTE)
        invoke(arena, "retire", handle, arena.bytes(report.encoded()), output)
        flag(output.get(JAVA_BYTE, 0).toInt())
    }
    @JvmSynthetic internal fun accountBegin(handle: Long): AccountCleanupHeader =
        record(handle, "account_begin", accountCleanupHeaderLayout) { fields ->
            val operation = fields.bytes("batch", 32)
            val report = fields.bytes("report", 32)
            val count = uint(fields.integer("member_count"))
            if (fields.integer("reserved_zero") != 0 || count !in 1..32 ||
                operation.all { it == 0.toByte() } || report.all { it == 0.toByte() }) {
                malformed("native account cleanup header differs")
            }
            AccountCleanupHeader(AccountOperationID(operation), AccountAbandonmentID(report), count)
        }
    @JvmSynthetic internal fun accountCleanupStatus(handle: Long): AccountStatus =
        record(handle, "account_cleanup_status", statusLayout) { fields ->
            decodeAccountStatus(fields.integer("phase"), fields.bytes("report", 32))
        }
    @JvmSynthetic internal fun accountReconciliation(handle: Long): AccountReconciliation = Arena.ofConfined().use { arena ->
        val output = arena.allocate(accountReconciliationLayout)
        invoke(arena, "account_reconciliation", handle, output)
        decodeAccountReconciliation(output.toArray(JAVA_BYTE))
    }
    @JvmSynthetic internal fun decodeAccountReconciliation(bytes: ByteArray): AccountReconciliation {
        if (bytes.size != 2856) malformed("native account reconciliation width differs")
        val record = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder())
        val count = record.getInt(32)
        val operation = bytes.copyOfRange(0, 32)
        if (count !in 1..32 || record.getInt(36) != 0 || operation.all { it == 0.toByte() }) {
            malformed("native account reconciliation scope differs")
        }
        val members = mutableListOf<AccountReconciledMember>()
        for (index in 0 until 32) {
            val offset = 40 + index * 88
            val member = bytes.copyOfRange(offset, offset + 88)
            if (index >= count) {
                if (member.any { it != 0.toByte() }) malformed("native unused account member is not zero")
                continue
            }
            val device = member.copyOfRange(0, 16)
            val session = member.copyOfRange(16, 48)
            val message = member.copyOfRange(48, 80)
            val state = AccountMemberState.entries.singleOrNull { it.code == record.getInt(offset + 80) }
                ?: malformed("native account member state differs")
            val previous = members.lastOrNull()?.device?.encoded()
            val firstDifference = previous?.let { old -> old.indices.firstOrNull { old[it] != device[it] } }
            if (record.getInt(offset + 84) != 0 || device.all { it == 0.toByte() } ||
                session.all { it == 0.toByte() } || message.all { it == 0.toByte() } ||
                (previous != null && (firstDifference == null ||
                    (previous[firstDifference].toInt() and 255) >= (device[firstDifference].toInt() and 255)))) {
                malformed("native account member identity/order differs")
            }
            members.add(AccountReconciledMember(PublicBytes(device), SessionID(session), MessageID(message), state))
        }
        return AccountReconciliation(AccountOperationID(operation), members)
    }
    @JvmSynthetic internal fun accountMember(handle: Long, member: Long): AccountCleanupMember =
        record(handle, "account_member", accountCleanupMemberLayout, listOf(index(member))) { fields ->
            val device = fields.bytes("device", 16)
            val session = fields.bytes("session", 32)
            val generation = fields.counter("generation")
            val count = uint(fields.integer("epoch_count"))
            val role = SessionRole.entries.singleOrNull { it.code == fields.integer("role") }
                ?: malformed("native account cleanup role differs")
            if (fields.integer("reserved_zero") != 0 || generation == Counter64.ZERO || count !in 1..4 ||
                device.all { it == 0.toByte() } || session.all { it == 0.toByte() }) {
                malformed("native account cleanup member differs")
            }
            AccountCleanupMember(PublicBytes(device), PublicBytes(fields.bytes("context", 32)), SessionID(session),
                generation, role, fields.counter("confirmed_epoch"), fields.counter("sending_epoch"),
                fields.counter("receiving_epoch"), fields.optional("has_pending_epoch", "pending_epoch"), count)
        }
    @JvmSynthetic internal fun accountReservation(handle: Long, member: Long): ReservedLoss =
        record(handle, "account_reserved", reservedLayout, listOf(index(member))) {
            ReservedLoss(MessageID(it.bytes("message", 32)), it.counter("plaintext_bytes"), it.counter("associated_data_bytes"))
        }
    @JvmSynthetic internal fun accountEpoch(handle: Long, member: Long, epoch: Long): ClosureEpoch =
        record(handle, "account_epoch", epochLayout, listOf(index(member), index(epoch)), ::decodeEpoch)
    @JvmSynthetic internal fun accountUnconfirmed(handle: Long, member: Long, epoch: Long, at: Long): UnconfirmedLoss =
        record(handle, "account_unconfirmed", unconfirmedLayout, listOf(index(member), index(epoch), index(at))) {
            UnconfirmedLoss(MessageID(it.bytes("message", 32)), PublicBytes(it.bytes("ciphertext_digest", 32)))
        }
    @JvmSynthetic internal fun accountDelivery(handle: Long, member: Long, epoch: Long, at: Long): DeliveryLoss =
        record(handle, "account_delivery", deliveryLayout, listOf(index(member), index(epoch), index(at))) {
            DeliveryLoss(MessageID(it.bytes("message", 32)), it.counter("index"), it.counter("plaintext_bytes"))
        }
    @JvmSynthetic internal fun accountSkipped(handle: Long, member: Long, epoch: Long, at: Long): Counter64 =
        Arena.ofConfined().use { arena ->
            val selectedMember = index(member)
            val selectedEpoch = index(epoch)
            val selectedIndex = index(at)
            val output = arena.allocate(JAVA_LONG)
            invoke(arena, "account_skipped", handle, selectedMember, selectedEpoch, selectedIndex, output)
            Counter64.fromBits(output.get(JAVA_LONG, 0))
        }
    @JvmSynthetic internal fun layouts(): Map<String, Pair<Long, Long>> = mapOf(
        "error" to errorLayout, "witness" to witnessLayout, "options" to optionsLayout,
        "enrollment_intent" to enrollmentIntentLayout, "checkpoint" to checkpointLayout, "enrollment_pin" to enrollmentPinLayout,
        "enrollment_status" to enrollmentStatusLayout, "enrollment_request" to enrollmentRequestLayout,
        "roster_resolution" to rosterResolutionLayout,
        "credential_renewal_status" to credentialRenewalStatusLayout,
        "credential_renewal_proposal" to credentialRenewalProposalLayout,
        "credential_renewal_cancellation" to credentialRenewalCancellationLayout,
        "policy_renewal_scope" to policyRenewalScopeLayout,
        "policy_renewal_request" to policyRenewalRequestLayout,
        "policy_renewal_status" to policyRenewalStatusLayout,
        "independent_policy_proposal" to independentPolicyProposalLayout,
        "independent_policy_preparation" to independentPolicyPreparationLayout,
        "independent_policy_progress" to independentPolicyProgressLayout,
        "policy_document" to policyDocumentLayout,
        "policy_renewal_proposal" to policyRenewalProposalLayout,
        "policy_renewal_cancellation" to policyRenewalCancellationLayout,
        "setup_status" to setupStatusLayout, "setup_preparation" to setupPreparationLayout,
        "served" to servedLayout, "header" to headerLayout, "epoch" to epochLayout,
        "reserved" to reservedLayout, "unconfirmed" to unconfirmedLayout,
        "delivery" to deliveryLayout, "status" to statusLayout,
        "account_target" to accountTargetLayout, "account_delivery" to accountDeliveryLayout,
        "account_cleanup_header" to accountCleanupHeaderLayout, "account_cleanup_member" to accountCleanupMemberLayout,
        "account_reconciled_member" to accountReconciledMemberLayout, "account_reconciliation" to accountReconciliationLayout,
    ).mapValues { (_, layout) -> layout.byteSize() to layout.byteAlignment() }
    @JvmSynthetic internal fun policyRenewalOffsets(): Map<String, Long> = mapOf(
        "scope_current_roster" to offset(policyRenewalScopeLayout, "current_roster"),
        "scope_previous_authorization" to offset(policyRenewalScopeLayout, "previous_authorization"),
        "scope_reserved" to offset(policyRenewalScopeLayout, "reserved"),
        "request_original_checkpoint" to offset(policyRenewalRequestLayout, "original_roster_checkpoint"),
        "request_original_credential" to offset(policyRenewalRequestLayout, "original_credential"),
        "status_target" to offset(policyRenewalStatusLayout, "target"),
        "status_observed_at" to offset(policyRenewalStatusLayout, "observed_at"),
    )
    @JvmSynthetic internal fun policyDocumentOffsets(): Map<String, Long> =
        listOf("root", "root_length", "family", "version", "digest", "wire", "wire_length").associateWith {
            offset(policyDocumentLayout, it)
        }
    @JvmSynthetic internal fun credentialRenewalOffsets(): Map<String, Long> =
        listOf("phase", "operation", "statement", "checkpoint", "observed_at").associateWith {
            offset(credentialRenewalStatusLayout, it)
        }
}
