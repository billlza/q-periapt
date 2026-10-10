// SPDX-License-Identifier: Apache-2.0 OR MIT
package configuration

import dev.qperiapt.continuity.*
import java.lang.ref.Reference
import java.lang.ref.ReferenceQueue
import java.lang.ref.WeakReference
import java.lang.management.ManagementFactory
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermissions

private fun load(source: Path, name: String, maximum: Int): ByteArray =
    Files.newInputStream(source.resolve(name)).use {
        it.readNBytes(maximum + 1).also { bytes -> check(bytes.size in 1..maximum) { "input width: $name" } }
    }
private fun exact(source: Path, name: String, count: Int) = load(source, name, count).also { check(it.size == count) }
private fun counter(bytes: ByteArray) = Counter64.parse(java.lang.Long.toUnsignedString(ByteBuffer.wrap(bytes).long))
private fun write(bytes: ByteArray, path: String) {
    Files.newByteChannel(Path.of(path), setOf(CREATE_NEW, WRITE),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) check(channel.write(buffer) > 0) { "zero progress writing public output" }
    }
}
private fun trust(source: Path, recoverable: Boolean): SdkPolicyTrust {
    val root = exact(source, "sdk-root", 1952)
    return if (recoverable) SdkPolicyTrust.recoverable(exact(source, "recovery-scope", 32), root, exact(source, "recovery-root", 1952))
        else SdkPolicyTrust.fixed(root)
}
private fun policy(source: Path) = PolicyDocument(exact(source, "policy-root", 1985), exact(source, "family", 32),
    PolicyCheckpoint(counter(exact(source, "policy-version", 8)), exact(source, "policy-digest", 32)), load(source, "protocol-policy", 8192))
private fun tls(source: Path, prefix: String): LocalTlsIdentity {
    val key = load(source, "$prefix-key", 8192)
    try { return LocalTlsIdentity(load(source, "$prefix-cert", 8192), key) } finally { key.fill(0) }
}
private fun initial(source: Path, recoverable: Boolean, identity: LocalTlsIdentity) = InstallationConfiguration(
    InitialSdkPolicy(trust(source, recoverable), load(source, "sdk-policy", 65536), exact(source, "sdk-signature", 3309),
        if (recoverable) exact(source, "recovery-enrollment", 3309) else null), policy(source), identity)
private fun prepareInitial(source: Path, target: String, recoverable: Boolean, reconcile: Boolean): ContinuityConfiguration =
    tls(source, "tls").use { identity ->
        val input = initial(source, recoverable, identity)
        if (reconcile) ContinuityConfiguration.prepareReconcile(target, input) else ContinuityConfiguration.prepareCreate(target, input)
    } // Close all Kotlin private input snapshots BEFORE any finishOpen call.
private fun <T> withWitness(source: Path, carrier: String?, wrong: Boolean, body: (ConfigurationWitness?) -> T): T {
    if (carrier == null) return body(null)
    val identity = exact(source, "witness-id", 32)
    if (wrong) identity[0] = (identity[0].toInt() xor 1).toByte()
    val key = exact(source, "witness-public", 1985)
    val address = load(source, "witness-address", 128).decodeToString(throwOnInvalidSequence = true)
    if (carrier == "signed") return body(ConfigurationWitness.signedTCP(identity, key, address, 3000))
    check(carrier == "tls")
    return tls(source, "witness-tls").use { local ->
        body(ConfigurationWitness.mutualTLS(identity, key, address, 3000, load(source, "witness-tls-peer", 8192),
            load(source, "witness-tls-name", 128).decodeToString(throwOnInvalidSequence = true), local))
    }
}
private fun traffic(device: ContinuityDevice, source: Path, mode: String): ByteArray {
    val input = consumer.peerConfiguration(source.resolve("peer").toString())
    val address = load(source,"connection-address",128).decodeToString(throwOnInvalidSequence = true)
    val session = if (mode == "connect") null else SessionID(exact(source,"connection-session",32))
    val pending = if (session == null) device.preparePeer(input,PrekeyQuality.ONE_TIME_BOTH,BootstrapRole.INITIATOR)
        else device.preparePeerReopen(input,PrekeyQuality.ONE_TIME_BOTH,BootstrapRole.INITIATOR,session)
    return pending.use { peer ->
        peer.finishOpen()
        if (session == null) peer.establish(address,InitiationID(exact(source,"connection-initiation",32))).session.encoded()
        else {
            val uncertain = mode == "uncertain-send"
            val message = if (uncertain) peer.nextMessage(session) else MessageID(exact(source,"connection-message",32))
            try {
                val sent = peer.send(address,session,message,"persisted before process exit".encodeToByteArray(),"configuration-v1".encodeToByteArray())
                check(!uncertain && sent.consumption == Consumption.CONFIRMED) { "incorrect delivery result" }
            } catch (failure: ContinuityFailure) {
                if (!uncertain || failure.code !in setOf(303,309,310,311)) throw failure
            }
            check(peer.messageStatus(session,message) == if (uncertain) MessageStatus.COMMITTED else MessageStatus.ACKNOWLEDGED) { "original message status differs" }
            session.encoded() + message.encoded()
        }
    }
}
private fun expect(code: Int, body: () -> Unit) {
    try { body(); error("expected native refusal $code") } catch (failure: ContinuityFailure) {
        if (failure.code != code) throw failure
    }
}
private fun closeAll(values: List<AutoCloseable>, original: Throwable? = null) {
    var failure = original
    for (value in values) try { value.close() } catch (next: Throwable) {
        if (failure == null) failure = next else failure.addSuppressed(next)
    }
    failure?.let { throw it }
}
private fun preparedPool(source: Path, target: String, recoverable: Boolean): List<ContinuityConfiguration> {
    val owners = ArrayList<ContinuityConfiguration>()
    try {
        repeat(64) { owners.add(prepareInitial(source, "$target.$it", recoverable, false)) }
        expect(4) { prepareInitial(source, "$target.overflow", recoverable, false).use { it.cancel() } }
        return owners
    } catch (failure: Throwable) { closeAll(owners, failure); throw failure }
}
private fun forgetPool(source: Path, target: String, recoverable: Boolean, queue: ReferenceQueue<ContinuityConfiguration>): List<WeakReference<ContinuityConfiguration>> =
    preparedPool(source, target, recoverable).map { WeakReference(it, queue) }
private fun pressure() {
    val buffers = Array(8) { index -> ByteArray(1024 * 1024) { index.toByte() } }
    check(buffers.sumOf { it.first().toInt() + it.last().toInt() } == 56)
    System.gc(); Reference.reachabilityFence(buffers)
}
private fun gcCapacity(source: Path, target: String, recoverable: Boolean) {
    check(Runtime.getRuntime().maxMemory() in 64L * 1024 * 1024..128L * 1024 * 1024)
    val before = ManagementFactory.getGarbageCollectorMXBeans().sumOf { it.collectionCount.also { n -> check(n >= 0) } }
    val queue = ReferenceQueue<ContinuityConfiguration>()
    val weak = forgetPool(source, target, recoverable, queue)
    val pending = weak.toMutableSet()
    var restored: List<ContinuityConfiguration>? = null
    for (round in 0 until 32) {
        pressure()
        while (true) { val collected = queue.poll() ?: break; check(pending.remove(collected)) }
        if (pending.isEmpty()) {
            check(weak.all { it.get() == null })
            try { restored = preparedPool(source, "$target.replacement", recoverable); break }
            catch (failure: ContinuityFailure) { if (failure.code != 4 || failure.suppressed.isNotEmpty()) throw failure }
        }
        Thread.sleep(10)
    }
    val owners = checkNotNull(restored) { "collected configuration owners did not return all 64 native slots" }
    try {
        pressure()
        expect(4) { prepareInitial(source, "$target.live-overflow", recoverable, false).use { it.cancel() } }
    } catch (failure: Throwable) { closeAll(owners, failure); throw failure }
    closeAll(owners)
    Reference.reachabilityFence(owners)
    repeat(64) { check(Files.notExists(Path.of("$target.$it"))) { "preparation wrote files" } }
    val after = ManagementFactory.getGarbageCollectorMXBeans().sumOf { it.collectionCount }
    check(after > before) { "no observed collection" }
}
private fun targetLease(enrollment: ContinuityEnrollment, source: Path, path: String, recoverable: Boolean, reject: Boolean) {
    val inputs = if (reject) source else source.resolve("continuation")
    val targetPath = path + if (reject) ".rejected-target" else ".continued-target"
    prepareInitial(inputs, targetPath, recoverable, false).use { target ->
        target.finishOpen()
        if (reject) {
            expect(103) { target.selectContinuationTarget(enrollment) }
            for ((directory, config) in listOf(path to source, targetPath to inputs)) {
                ContinuityConfiguration.prepareOpen(directory, trust(config, recoverable), policy(config)).use { it.finishOpen() }
            }
        } else {
            target.selectContinuationTarget(enrollment)
            target.close()
            expect(2) { target.cancel() }
            ContinuityConfiguration.prepareOpen(targetPath, trust(inputs, recoverable), policy(inputs)).use { busy -> expect(703) { busy.finishOpen() } }
        }
        enrollment.close()
        ContinuityConfiguration.prepareOpen(targetPath, trust(inputs, recoverable), policy(inputs)).use { it.finishOpen() }
        Reference.reachabilityFence(target)
    }
}
private fun policyStatusBytes(value: PolicyRenewalStatus): ByteArray {
    val b=ByteBuffer.allocate(160).order(java.nio.ByteOrder.nativeOrder())
    fun checkpoint(version: Counter64,digest: PublicBytes) { b.putLong(java.lang.Long.parseUnsignedLong(version.toString())); b.put(digest.encoded()) }
    fun record(phase:Int,operation:PolicyRenewalID,statement:PolicyRenewalStatementID,target:PolicyCheckpoint,
               reason:Int=0,roster:RosterCheckpoint?=null,at:Counter64=Counter64.ZERO) {
        b.putInt(phase); b.putInt(reason); b.put(operation.encoded()); b.put(statement.encoded()); checkpoint(target.version,target.digest)
        if(roster==null) b.put(ByteArray(40)) else checkpoint(roster.version,roster.digest)
        b.putLong(java.lang.Long.parseUnsignedLong(at.toString()))
    }
    when(value) {
        PolicyRenewalStatus.Absent -> b.put(ByteArray(160))
        is PolicyRenewalStatus.Pending -> record(1,value.operation,value.statement,value.target)
        is PolicyRenewalStatus.Committed -> record(2,value.operation,value.statement,value.target)
        is PolicyRenewalStatus.AbandonedUncommitted -> record(3,value.operation,value.statement,value.target,
            when(value.reason){PolicyRenewalAbandonment.EXPIRED->1;PolicyRenewalAbandonment.ROSTER_ADVANCED->2},value.observedRoster,value.observedAt)
    }
    check(!b.hasRemaining()); return b.array()
}
private fun selectPolicyTarget(owner:ContinuityEnrollment,source:Path,target:String,recoverable:Boolean) {
    val input=source.resolve("policy-target")
    ContinuityConfiguration.prepareOpen("$target.policy-target",trust(input,recoverable),policy(input)).use {
        it.finishOpen(); it.selectContinuationTarget(owner)
    }
}
private fun policyOperation(owner:ContinuityEnrollment,source:Path,target:String,recoverable:Boolean,carrier:String?,mode:String):ByteArray {
    if(mode=="policy-request") {
        val operation=PolicyRenewalID(exact(source,"renewal-operation",32))
        val request=if(carrier==null) owner.policyRenewalRequest(operation) else owner.witnessedPolicyRenewalRequest(operation)
        return consumer.IndependentRequestFixture.write(request)
    }
    if(mode=="policy-witness-recover") return checkNotNull(owner.recoverWitnessedPolicyRenewalPreparation()).encoded()
    if(mode!="policy-witness-reconcile") selectPolicyTarget(owner,source,target,recoverable)
    return when(mode) {
        "policy-witness-prepare" -> owner.prepareWitnessedPolicyRenewal(policy(source)).encoded()
        "policy-witness-commit", "policy-witness-reconcile" -> {
            val proposal=IndependentPolicyProposal.fromRetained(exact(source,"renewal-proposal",296))
            val state=if(mode=="policy-witness-commit") owner.commitWitnessedPolicyRenewal(proposal) else owner.reconcileWitnessedPolicyRenewal(proposal)
            ByteBuffer.allocate(4).order(java.nio.ByteOrder.nativeOrder()).putInt(state.code).array()
        }
        "policy-stage", "policy-stage-refused" -> {
            val request=consumer.IndependentRequestFixture.read(exact(source,"renewal-request",33176))
            val pin=AccountPin(AccountID(exact(source,"trusted-account",32)),exact(source,"enrollment-root",1985),exact(source,"family",32),
                RosterCheckpoint(counter(exact(source,"trusted-roster-version",8)),exact(source,"trusted-roster-digest",32)))
            val approvals=load(source,"renewal-approvals",8192)
            if(mode=="policy-stage-refused") {
                approvals[approvals.lastIndex]=(approvals.last().toInt() xor 1).toByte()
                expect(102) { owner.stagePolicyRenewal(request,pin,pin,approvals,policy(source)) }
                expect(2) { owner.status() }
                ByteBuffer.allocate(4).order(java.nio.ByteOrder.nativeOrder()).putInt(102).array()
            } else policyStatusBytes(owner.stagePolicyRenewal(request,pin,pin,approvals,policy(source)))
        }
        "policy-reconcile" -> policyStatusBytes(owner.reconcilePolicyRenewal())
        else -> error("policy mode")
    }
}

fun main(args: Array<String>) {
    check(args.size in 5..6) { "argument count" }
    val mode = args[0]; val recoverable = when (args[1]) { "fixed" -> false; "recoverable" -> true; else -> error("profile") }
    check(mode in setOf("create", "resume", "reconcile", "reconcile-refused", "cancel-create", "gc-capacity", "select-target", "select-target-reject",
        "prepare", "activate", "activate-expired", "activate-missing", "activate-bad-receipt", "wrong-witness", "cancel", "enroll-local", "connect", "uncertain-send", "retry-send", "retry-policy", "policy-target-create", "policy-request", "policy-stage-refused", "policy-stage", "policy-reconcile", "policy-witness-prepare", "policy-witness-recover", "policy-witness-commit", "policy-witness-reconcile")) { "mode" }
    val source = Path.of(args[2]); val target = args[3]; val output = args[4]; val carrier = args.getOrNull(5)
    if (mode == "gc-capacity") { gcCapacity(source, target, recoverable); println("QPC_CONFIGURATION_GC_PASS"); return }
    if (mode == "policy-target-create") {
        prepareInitial(source,target,recoverable,false).use { it.finishOpen() }; println("QPC_CONFIGURATION_POLICY_TARGET"); return
    }
    val configuration = when (mode) {
        "create", "cancel-create" -> prepareInitial(source, target, recoverable, false)
        "reconcile", "reconcile-refused" -> prepareInitial(source, target, recoverable, true)
        else -> ContinuityConfiguration.prepareOpen(target, trust(source, recoverable), policy(source))
    }
    var registration: ContinuityEnrollment? = null
    var device: ContinuityDevice? = null
    var failure: Throwable? = null
    var marker: String? = null
    try {
        when (mode) {
            "cancel-create" -> {
                configuration.cancel(); expect(302) { configuration.finishOpen() }
                check(Files.notExists(Path.of(target))); marker = "QPC_CONFIGURATION_CREATE_CANCELLED"
            }
            "reconcile-refused" -> { expect(107) { configuration.finishOpen() }; marker = "QPC_CONFIGURATION_RECONCILE_REFUSED" }
            else -> {
                configuration.finishOpen()
                val wire = exact(source, "enrollment-intent", 72)
                val intent = EnrollmentIntent(exact(source, "enrollment-root", 1985), wire.copyOfRange(0, 16), counter(wire.copyOfRange(16, 24)),
                    wire.copyOfRange(24, 56), counter(wire.copyOfRange(56, 64)), counter(wire.copyOfRange(64, 72)))
                if (mode == "cancel") configuration.cancel()
                if (mode == "wrong-witness" || mode == "cancel") {
                    expect(if (mode == "cancel") 302 else 103) {
                        withWitness(source, carrier, mode == "wrong-witness") { configuration.resumeEnrollment(intent, it).use { owner -> owner.cancel() } }
                    }
                    marker = if (mode == "cancel") "QPC_CONFIGURATION_CANCELLED" else "QPC_CONFIGURATION_WITNESS_SCOPE_REFUSED"
                } else {
                    val owner = withWitness(source, carrier, false) {
                        if (mode == "create") configuration.createEnrollment(intent, it) else configuration.resumeEnrollment(intent, it)
                    }
                    registration = owner
                    configuration.close()
                    var bytes = owner.request().encoded()
                    marker = "QPC_CONFIGURATION_REQUEST_PASS"
                    when (mode) {
                        "policy-request", "policy-stage-refused", "policy-stage", "policy-reconcile", "policy-witness-prepare", "policy-witness-recover", "policy-witness-commit", "policy-witness-reconcile" -> {
                            bytes=policyOperation(owner,source,target,recoverable,carrier,mode); marker="QPC_CONFIGURATION_POLICY_OPERATION"
                        }
                        "select-target", "select-target-reject" -> {
                            targetLease(owner, source, target, recoverable, mode == "select-target-reject"); registration = null
                            marker = if (mode == "select-target") "QPC_CONFIGURATION_TARGET_LEASE_PASS" else "QPC_CONFIGURATION_TARGET_FAILURE_PASS"
                        }
                        "prepare", "enroll-local" -> {
                            val pin = AccountPin(AccountID(exact(source, "trusted-account", 32)), exact(source, "enrollment-root", 1985), intent.family.encoded(),
                                RosterCheckpoint(counter(exact(source, "trusted-roster-version", 8)), exact(source, "trusted-roster-digest", 32)))
                            val journal = owner.accept(load(source, "grant-certificate", 8192), load(source, "grant-roster", 65536), pin)
                            val prepared = owner.prepareStorage()
                            if (mode == "enroll-local") {
                                check(prepared is InstallationPreparation.Local && prepared.journal == journal)
                                device = owner.activate(); owner.close(); marker = "QPC_CONFIGURATION_LOCAL_ACTIVE"
                            } else {
                                check(prepared is InstallationPreparation.RequiresEnrollment && prepared.genesis.journal == journal)
                                bytes = byteArrayOf(0, 0, 0, 2) + journal.encoded() + prepared.genesis.subject.encoded() + prepared.genesis.imageDigest.encoded()
                                marker = "QPC_CONFIGURATION_GENESIS_PASS"
                            }
                        }
                        "activate-expired" -> {
                            expect(104) { owner.activate().use { it.cancel() } }
                            expect(2) { owner.status() }
                            bytes = ByteBuffer.allocate(4).order(java.nio.ByteOrder.nativeOrder()).putInt(104).array()
                            marker = "QPC_CONFIGURATION_POLICY_EXPIRED"
                        }
                        "activate-missing", "activate-bad-receipt" -> {
                            expect(if (mode == "activate-missing") 216 else 218) { owner.activate().use { it.cancel() } }
                            marker = if (mode == "activate-missing") "QPC_CONFIGURATION_WITNESS_REQUIRED" else "QPC_CONFIGURATION_WITNESS_RECEIPT_REFUSED"
                        }
                        "connect", "uncertain-send", "retry-send", "retry-policy" -> {
                            if(mode=="retry-policy") selectPolicyTarget(owner,source,target,recoverable)
                            val active = if(mode=="retry-policy") owner.activatePolicyRenewal() else owner.activate(); device = active; owner.close()
                            bytes = traffic(active, source, mode)
                            marker = when(mode) { "connect" -> "QPC_CONFIGURATION_CONNECTION_PASS"; "uncertain-send" -> "QPC_CONFIGURATION_UNKNOWN_COMMITTED"; else -> "QPC_CONFIGURATION_ORIGINAL_ACKNOWLEDGED" }
                        }
                        "activate" -> { device = owner.activate(); owner.close(); marker = "QPC_CONFIGURATION_ACTIVATION_PASS" }
                    }
                    write(bytes, output)
                }
            }
        }
    } catch (caught: Throwable) { failure = caught }
    closeAll(listOfNotNull(device, registration, configuration), failure)
    println(checkNotNull(marker))
}
