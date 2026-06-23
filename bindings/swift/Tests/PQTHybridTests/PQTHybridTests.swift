import XCTest

@testable import PQTHybrid

/// Cross-platform consistency: decapsulate the shared Rust-generated vector and
/// assert the secret matches byte-for-byte. See bindings/shared-test-vectors.json.
final class PQTHybridTests: XCTestCase {
    func hex(_ s: String) -> [UInt8] {
        var out = [UInt8]()
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    func testSharedVectorDecapsulates() throws {
        // Path to the repo-root shared vector, relative to this source file.
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("shared-test-vectors.json")
        let data = try Data(contentsOf: url)
        let v = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        let secret = try PQTHybrid.decapsulate(
            profile: .contextBound,
            suiteId: hex(v["suite_id"] as! String),
            policyVersion: UInt32(v["policy_version"] as! Int),
            skPq: hex(v["sk_pq"] as! String),
            ctPq: hex(v["ct_pq"] as! String),
            pkPq: hex(v["pk_pq"] as! String),
            skTrad: hex(v["sk_trad"] as! String),
            ctTrad: hex(v["ct_trad"] as! String),
            pkTrad: hex(v["pk_trad"] as! String),
            context: hex(v["context"] as! String))

        XCTAssertEqual(secret, hex(v["secret"] as! String),
                       "Swift decapsulation must match the Rust core byte-for-byte")
    }
}
