// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer
import dev.qperiapt.continuity.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Path

/** Same-host fixture exchange with the C/Rust harness, not a network format.
 * Only public wrapper values are serialized; no native handles/codecs are used. */
internal object IndependentRequestFixture {
    private fun ByteBuffer.bytes(n: Int) = ByteArray(n).also { get(it) }
    private fun ByteBuffer.counter() = Counter64.parse(java.lang.Long.toUnsignedString(long))
    private fun ByteBuffer.roster() = RosterCheckpoint(counter(), bytes(32))
    private fun ByteBuffer.policy() = PolicyCheckpoint(counter(), bytes(32))
    private fun ByteBuffer.blob(): ByteArray {
        val length = int; val bytes = bytes(8192)
        check(length in 1..8192 && bytes.copyOfRange(length,8192).all { it == 0.toByte() })
        return bytes.copyOf(length)
    }
    fun read(bytes: ByteArray): PolicyRenewalRequest {
        check(bytes.size == 33176)
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder())
        val operation = PolicyRenewalID(b.bytes(32)); val journal = JournalID(b.bytes(32))
        val owner = b.bytes(32); val original = b.bytes(32); val current = b.bytes(32)
        val roster = b.roster(); val originalPolicy = b.policy(); val previousPolicy = b.policy(); val authorization = b.bytes(32)
        val previous = when (b.int) { 0 -> { check(authorization.all { it == 0.toByte() }); null }; 1 -> PolicyAuthorizationID(authorization); else -> error("bad optional authorization") }
        check(b.int == 0)
        val scope = PolicyRenewalScope(operation,journal,owner,original,current,roster,originalPolicy,previousPolicy,previous)
        return PolicyRenewalRequest(scope,AccountID(b.bytes(32)),b.roster(),b.blob(),b.blob(),b.blob(),b.blob()).also { check(!b.hasRemaining()) }
    }
    private fun ByteBuffer.counter(value: Counter64) { putLong(java.lang.Long.parseUnsignedLong(value.toString())) }
    private fun ByteBuffer.checkpoint(version: Counter64, digest: PublicBytes) { counter(version); put(digest.encoded()) }
    private fun ByteBuffer.blob(value: PublicBytes) { val bytes=value.encoded(); putInt(bytes.size); put(bytes); position(position()+8192-bytes.size) }
    fun write(request: PolicyRenewalRequest): ByteArray {
        val b=ByteBuffer.allocate(33176).order(ByteOrder.nativeOrder());val s=request.scope
        b.put(s.operation.encoded());b.put(s.journal.encoded());b.put(s.originalOwner.encoded());b.put(s.originalCredential.encoded());b.put(s.currentCredential.encoded())
        b.checkpoint(s.currentRoster.version,s.currentRoster.digest);b.checkpoint(s.originalPolicy.version,s.originalPolicy.digest);b.checkpoint(s.previousPolicy.version,s.previousPolicy.digest)
        b.put(s.previousAuthorization?.encoded() ?: ByteArray(32));b.putInt(if(s.previousAuthorization==null)0 else 1);b.putInt(0)
        b.put(request.account.encoded());b.checkpoint(request.originalRosterCheckpoint.version,request.originalRosterCheckpoint.digest)
        b.blob(request.originalCredential);b.blob(request.originalRoster);b.blob(request.currentCredential);b.blob(request.currentRoster)
        check(!b.hasRemaining());return b.array()
    }
}
private fun independentStatus(status: PolicyRenewalStatus): String {
    val zero="0".repeat(64)
    fun result(phase:Int,op:PolicyRenewalID,statement:PolicyRenewalStatementID,target:PolicyCheckpoint,reason:Int=0,roster:RosterCheckpoint?=null,at:Counter64=Counter64.ZERO)=
        listOf(phase.toString(),reason.toString(),hex(op),hex(statement),target.version.toString(),target.digest.encoded().joinToString(""){"%02x".format(it)},
            roster?.version?.toString() ?: "0",roster?.digest?.encoded()?.joinToString(""){"%02x".format(it)} ?: zero,at.toString()).joinToString("\n")
    return when(status) {
        PolicyRenewalStatus.Absent -> listOf("0","0",zero,zero,"0",zero,"0",zero,"0").joinToString("\n")
        is PolicyRenewalStatus.Pending -> result(1,status.operation,status.statement,status.target)
        is PolicyRenewalStatus.Committed -> result(2,status.operation,status.statement,status.target)
        is PolicyRenewalStatus.AbandonedUncommitted -> result(3,status.operation,status.statement,status.target,
            when(status.reason){PolicyRenewalAbandonment.EXPIRED->1;PolicyRenewalAbandonment.ROSTER_ADVANCED->2},status.observedRoster,status.observedAt)
    }
}
internal fun independentPolicyEnrollment(owner:ContinuityEnrollment,path:String,records:FixtureRecords,mode:String):String {
    if(mode.startsWith("witness-")) return witnessedIndependentPolicy(owner,path,records,mode.removePrefix("witness-"))
    val operation=PolicyRenewalID(records.enrollmentExact("independent-operation",32))
    when(mode) {
        "request" -> {
            val request=owner.policyRenewalRequest(operation)
            check(records.retain("independent-request",IndependentRequestFixture.write(request),true))
            return "request-saved"
        }
        "request-refused" -> { refused(setOf(215)){owner.policyRenewalRequest(operation)};refused(setOf(2)){owner.status()};return "request-refused:215" }
        "status" -> return independentStatus(owner.policyRenewalStatus())
        "pending" -> {check(owner.pendingPolicyRenewalApproval(operation).encoded().contentEquals(records.read("independent-first-approvals")));return "pending-exact"}
    }
    val targetPath=Path.of(path).resolve("independent-sdk");val target=policyDocument(targetPath)
    if(mode in setOf("resolve","resolve-pending","resolve-conflict","resolve-scope","resolve-cancelled")) {
        val statement=PolicyRenewalStatementID(records.enrollmentExact("independent-statement",32))
        val expected=when(mode){"resolve-pending"->215;"resolve-conflict"->211;"resolve-scope"->103;"resolve-cancelled"->302;else->0}
        if(expected==302) owner.cancel()
        if(expected!=0) {
            val failure=try {owner.resolvePolicyRenewal(operation,statement,target);error("historical resolution unexpectedly succeeded")}
                catch(failure:ContinuityFailure){failure}
            check(failure.code==expected){"wrong historical native error: $failure"}
            refused(setOf(if(expected==302)302 else 2)){owner.status()}
            return if(expected==215) "pending-unresolved:215" else "policy-resolve-refused:${failure.code}"
        }
        return independentStatus(owner.resolvePolicyRenewal(operation,statement,target))
    }
    owner.selectContinuedPolicy(targetPath.toString(),target)
    return when(mode) {
        "stage", "stage-corrupt-scope", "stage-corrupt-certificate", "stage-cancelled" -> {
            val retained=IndependentRequestFixture.read(records.read("independent-request"));val pin=enrollmentPin(records,false)
            val scope=retained.scope
            val selectedScope=if(mode=="stage-corrupt-scope") {
                val changed=scope.operation.encoded();changed[0]=(changed[0].toInt() xor 1).toByte()
                PolicyRenewalScope(PolicyRenewalID(changed),scope.journal,scope.originalOwner.encoded(),scope.originalCredential.encoded(),
                    scope.currentCredential.encoded(),scope.currentRoster,scope.originalPolicy,scope.previousPolicy,scope.previousAuthorization)
            } else scope
            val certificate=retained.originalCredential.encoded()
            if(mode=="stage-corrupt-certificate") certificate[certificate.lastIndex]=(certificate.last().toInt() xor 1).toByte()
            val request=PolicyRenewalRequest(selectedScope,retained.account,retained.originalRosterCheckpoint,certificate,
                retained.originalRoster.encoded(),retained.currentCredential.encoded(),retained.currentRoster.encoded())
            if(mode=="stage-cancelled") owner.cancel()
            val stage={owner.stagePolicyRenewal(request,pin,pin,records.read("independent-approvals"),policyDocument(Path.of(path)))}
            if(mode=="stage") independentStatus(stage()) else {
                val expected=when(mode){"stage-corrupt-scope"->103;"stage-corrupt-certificate"->102;"stage-cancelled"->302;else->error("unreachable stage mode")}
                val failure=try {stage();error("invalid policy request succeeded")} catch(failure:ContinuityFailure){failure}
                check(failure.code==expected){"wrong native policy refusal: $failure"}
                if(expected!=302) refused(setOf(2)){owner.status()}
                "stage-refused:${failure.code}"
            }
        }
        "reconcile" -> independentStatus(owner.reconcilePolicyRenewal())
        "activate" -> {
            owner.activatePolicyRenewal().use { successor -> owner.close();refused(setOf(2)){owner.status()};successor.nextAccountOperation() }
            "independent-device-active"
        }
        else -> error("unknown independent policy mode")
    }
}

private fun witnessedIndependentPolicy(owner: ContinuityEnrollment, path: String, records: FixtureRecords, mode: String): String {
    fun select() {
        val target = Path.of(path).resolve("independent-sdk")
        owner.selectContinuedPolicy(target.toString(), policyDocument(target))
    }
    fun retained() = IndependentPolicyProposal.fromRetained(records.enrollmentExact("independent-witness-proposal", 296))
    when (mode) {
        "request" -> {
            val operation = PolicyRenewalID(records.enrollmentExact("independent-operation", 32))
            val request = owner.witnessedPolicyRenewalRequest(operation)
            check(records.retain("independent-request", IndependentRequestFixture.write(request), true))
            return "request-saved"
        }
        "prepare" -> {
            select(); val previous = policyDocument(Path.of(path))
            val proposal = owner.prepareWitnessedPolicyRenewal(previous)
            check(owner.prepareWitnessedPolicyRenewal(previous) == proposal) { "P retry changed original sealed target" }
            check(records.retain("independent-witness-proposal", proposal.encoded(), true))
            return "proposal-saved"
        }
        "recover", "recover-absent" -> {
            val result = owner.recoverWitnessedPolicyRenewalPreparation()
            if (mode == "recover-absent") { check(result == null); return "preparation-absent" }
            check(result == retained()) { "original P preparation changed" }
            return "preparation-exact"
        }
        "progress" -> {
            fun record(phase: Int, proposal: IndependentPolicyProposal, target: PolicyCheckpoint, retired: Boolean): String {
                check(proposal == retained()) { "P progress changed original proposal" }
                return listOf(phase.toString(), if (retired) "1" else "0", target.version.toString(),
                    target.digest.encoded().joinToString("") { "%02x".format(it) }).joinToString("\n")
            }
            return when (val progress = owner.witnessedPolicyRenewalProgress()) {
                IndependentPolicyProgress.Absent -> "0\n0\n0\n" + "0".repeat(64)
                is IndependentPolicyProgress.Reserved -> record(1, progress.proposal, progress.target, false)
                is IndependentPolicyProgress.Applied -> record(2, progress.proposal, progress.target, progress.retired)
                is IndependentPolicyProgress.Closed -> record(3, progress.proposal, progress.target, progress.retired)
            }
        }
    }
    require(mode in setOf("commit", "commit-lost", "close", "close-lost", "reconcile", "reconcile-lost", "substitute", "cancelled")) { "unknown witness P mode" }
    val bytes = retained().encoded()
    if (mode == "substitute") bytes[295] = (bytes[295].toInt() xor 1).toByte()
    val proposal = IndependentPolicyProposal.fromRetained(bytes)
    if (mode == "cancelled") owner.cancel()
    val expected = when { mode == "substitute" -> 211; mode == "cancelled" -> 302; mode.endsWith("-lost") -> 218; else -> 0 }
    val command: () -> IndependentPolicyState = when (mode) {
        "commit", "commit-lost" -> { select(); { owner.commitWitnessedPolicyRenewal(proposal) } }
        "close", "close-lost" -> { { owner.closeWitnessedPolicyRenewal(proposal) } }
        else -> { { owner.reconcileWitnessedPolicyRenewal(proposal) } }
    }
    if (expected != 0) {
        val failure = try { command(); error("witness P failure was accepted") } catch (failure: ContinuityFailure) { failure }
        check(failure.code == expected) { "unexpected witness P failure: $failure" }
        refused(setOf(if (expected == 302) 302 else 2)) { owner.status() }
        return "witness-refused:$expected"
    }
    return "witness-state:${command().code}"
}
