// SPDX-License-Identifier: Apache-2.0 OR MIT
import XCTest
@testable import QPeriaptConnectionProbe

@available(macOS 13.0, *)
final class ArgumentsTests: XCTestCase {
    private let baseArguments = ["/private/fixture", "9443", "roundtrip", "localhost", "provision"]

    func testExplicitAddressKeepsCertificateNameAndDefaultLoopbackSeparate() throws {
        let local = try ConnectionProbe.Arguments(baseArguments)
        XCTAssertEqual(local.host, "127.0.0.1")
        XCTAssertEqual(local.port, 9443)
        for host in ["::1", "192.0.2.1", "server.example"] {
            let selected = try ConnectionProbe.Arguments(baseArguments + ["--host", host])
            XCTAssertEqual(selected.host, host)
            XCTAssertEqual(selected.serverName, "localhost")
            XCTAssertEqual(selected.action, "provision")
            XCTAssertEqual(selected.folder.path, "/private/fixture")
        }
    }

    func testAddressCannotBypassScenarioBudgetsOrObservedCancellation() throws {
        for scenario in ["cancel", "request-cancel", "runtime-revoke"] {
            var fields = baseArguments
            fields[2] = scenario
            XCTAssertThrowsError(try ConnectionProbe.Arguments(fields + ["--host", "::1"]))
            let selected = try ConnectionProbe.Arguments(fields + ["observed-io", "--host", "::1"])
            XCTAssertEqual(selected.scenario, scenario)
            XCTAssertEqual(selected.reconnects, 0)
        }
        var measure = baseArguments
        measure[2] = "measure"
        XCTAssertEqual(try ConnectionProbe.Arguments(measure + ["200", "--host", "::1"]).reconnects, 200)
        for count in ["0", "199", "1001", "invalid"] {
            XCTAssertThrowsError(try ConnectionProbe.Arguments(measure + [count, "--host", "::1"]))
        }
    }

    func testStoreOnlyScenariosPreserveTheirUnusedZeroPort() throws {
        for scenario in ["store-rollback", "store-disabled"] {
            let selected = try ConnectionProbe.Arguments(["/private/fixture", "0", scenario, "localhost", "open"])
            XCTAssertEqual(selected.port, 0)
            XCTAssertEqual(selected.scenario, scenario)
        }
    }

    func testInvalidInvocationIsRejectedBeforeAnyPolicyStoreIsOpened() {
        var invalid = [[String](), Array(baseArguments.prefix(4)), baseArguments + ["--host"],
                       baseArguments + ["unexpected"], baseArguments + ["--host", "::1", "--host", "::1"]]
        for host in ["", "has space", "127.0.0.1\n", "\u{0}", String(repeating: "a", count: 254)] {
            invalid.append(baseArguments + ["--host", host])
        }
        for (index, value) in [(0, ""), (1, "0"), (1, "65536"), (1, "-1"),
                               (2, "unknown"), (4, "unexpected-action")] {
            var fields = baseArguments
            fields[index] = value
            invalid.append(fields)
        }
        for fields in invalid {
            XCTAssertThrowsError(try ConnectionProbe.Arguments(fields)) { error in
                guard case ProbeError.usage = error else {
                    return XCTFail("expected argument rejection, got \(error)")
                }
            }
        }
    }
}
