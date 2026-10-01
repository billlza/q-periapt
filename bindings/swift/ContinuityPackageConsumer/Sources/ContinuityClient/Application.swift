// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation
import QPeriaptContinuity
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Test-application transaction only; no cryptographic/protocol state is implemented here.
/// Effect and deduplication bytes share one exclusive name and are synced before success.
final class Application {
    let path: String
    var calls = 0
    var created = 0
    init(path: String) { self.path = path }

    func persist(_ delivery: ReceivedMessage) throws {
        try require(delivery.plaintext == Array("persisted before process exit".utf8), "application payload differs")
        let bytes = delivery.session.bytes + delivery.message.bytes + delivery.plaintext
        let name = "application-" + hex(delivery.message)
        if try FixtureRecords(path: path).retain(name, bytes: bytes, create: true) { created += 1 }
    }
}

func serve(_ owner: ContinuityOwner, path: String, mode: String, sessionText: String?) throws {
    try require(["bootstrap", "message", "fail-before", "uncertain", "crash-after", "rekey", "pre-cancel", "deadline"].contains(mode), "unknown server mode")
    let application = Application(path: path)
    let port = try owner.listen(address: "127.0.0.1:0")
    try output("listening:\(port)")
    try failure([108]) { try owner.listen(address: "127.0.0.1:0") }
    if mode == "rekey" {
        guard let sessionText else { throw ProbeFailure.contract("missing rekey session") }
        try require(owner.serveRekey(session: decode(sessionText)) == 1, "server rekey target")
        try output("server-rekey-1")
        return
    }
    if mode == "pre-cancel" { try owner.cancel() }
    do {
        let event = try owner.serve { delivery in
            application.calls += 1
            try failure([3]) { try owner.close() }
            if mode == "fail-before" { throw try ApplicationCommitRefusal(status: 17, reason: "before application commit") }
            try application.persist(delivery)
            if mode == "uncertain" { throw try ApplicationCommitRefusal(status: 29, reason: "application commit outcome unknown") }
            if mode == "crash-after" { exit(77) }
        }
        try require(mode == "bootstrap" || mode == "message", "failure reported consumption")
        switch event {
        case let .established(session):
            try output("served:1:0:\(application.calls):\(application.created)")
            try output(hex(session)); try output(String(repeating: "0", count: 64))
        case let .consumed(session, message, duplicate):
            try output("served:2:\(duplicate ? 1 : 0):\(application.calls):\(application.created)")
            try output(hex(session)); try output(hex(message))
        }
    } catch let error as ContinuityApplicationFailure {
        guard let native = error.nativeError as? ContinuityFailure,
              let original = error.applicationError as? ApplicationCommitRefusal else { throw error }
        try require(native.code == 308 && application.calls == 1, "callback failure native outcome")
        let expected: Int32 = mode == "fail-before" ? 17 : 29
        try require((mode == "fail-before" || mode == "uncertain") && original.status == expected &&
                    native.message.contains("callback returned \(expected);"), "callback failure cause replaced")
        try output("application-failed:\(application.calls):\(application.created)")
    } catch let error as ContinuityFailure {
        try require(application.calls == 0, "cancelled/deadline server invoked application")
        if mode == "pre-cancel" && error.code == 302 { try output("server-cancelled") }
        else if mode == "deadline" && error.code == 303 { try output("server-deadline") }
        else { throw error }
    }
}
