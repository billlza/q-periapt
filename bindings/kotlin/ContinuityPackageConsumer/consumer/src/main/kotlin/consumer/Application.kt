// SPDX-License-Identifier: Apache-2.0 OR MIT
package consumer

import dev.qperiapt.continuity.*
import java.nio.file.Path
import kotlin.system.exitProcess

internal fun serve(owner: ContinuityOwner, path: String, mode: String, session: String?): String {
    require(mode in setOf("bootstrap", "message", "fail-before", "uncertain", "crash-after", "rekey", "pre-cancel", "deadline"))
    require((mode == "rekey") == (session != null)) { "rekey requires exactly one session" }
    val records = FixtureRecords(Path.of(path))
    var calls = 0
    var created = 0
    output("listening:${owner.listen("127.0.0.1:0")}")
    refused(setOf(108)) { owner.listen("127.0.0.1:0") }
    if (mode == "rekey") {
        check(owner.serveRekey(SessionID(decode(requireNotNull(session)))) == Counter64.of(1))
        return "server-rekey-1"
    }
    if (mode == "pre-cancel") owner.cancel()
    try {
        val event = owner.serve { delivery ->
            calls += 1
            refused(setOf(3)) { owner.close() }
            if (mode == "fail-before") throw ApplicationCommitRefusal(17, "before application commit")
            val payload = delivery.plaintext()
            check(payload.contentEquals("persisted before process exit".toByteArray())) { "application payload differs" }
            if (records.retain("application-${hex(delivery.message)}",
                    delivery.session.encoded() + delivery.message.encoded() + payload, true)) created += 1
            if (mode == "uncertain") throw ApplicationCommitRefusal(29, "application commit outcome unknown")
            if (mode == "crash-after") exitProcess(77)
        }
        check(mode == "bootstrap" || mode == "message") { "failure reported consumption" }
        return when (event) {
            is Served.Bootstrap -> "served:1:0:$calls:$created\n${hex(event.session)}\n${"0".repeat(64)}"
            is Served.Message -> "served:2:${if (event.duplicate) 1 else 0}:$calls:$created\n${hex(event.session)}\n${hex(event.message)}"
        }
    } catch (failure: ContinuityCallbackFailure) {
        val original = failure.cause as? ApplicationCommitRefusal ?: throw failure
        val expected = if (mode == "fail-before") 17 else 29
        check(mode in setOf("fail-before", "uncertain") && original.status == expected && calls == 1 &&
            failure.nativeFailure.code == 308 && failure.nativeFailure.diagnostic.contains("callback returned $expected;")) {
            "callback failure cause or native outcome replaced"
        }
        return "application-failed:$calls:$created"
    } catch (failure: ContinuityFailure) {
        check(calls == 0) { "cancelled/deadline server invoked application" }
        if (mode == "pre-cancel" && failure.code == 302) return "server-cancelled"
        if (mode == "deadline" && failure.code == 303) return "server-deadline"
        throw failure
    }
}
