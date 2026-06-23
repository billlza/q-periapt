import XCTest

@testable import QPeriaptHybrid

/// Cross-platform consistency: decapsulate the shared Rust-generated vector and
/// assert the secret matches byte-for-byte. See bindings/shared-test-vectors.json.
final class QPeriaptHybridTests: XCTestCase {
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

        let secret = try QPeriaptHybrid.decapsulate(
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

    /// Cross-platform combiner reference vectors: feed each `input` blob to the C ABI
    /// `combine` and assert the 32-byte key matches (bindings/contextbound-vectors.txt).
    func testCombineReferenceVectors() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("contextbound-vectors.txt")
        let text = try String(contentsOf: url, encoding: .utf8)
        var n = 0
        for line in text.split(separator: "\n") {
            let p = line.split(separator: " ")
            if p.count != 3 { continue }
            let profile = QPeriaptProfile(rawValue: UInt8(p[0])!)!
            let got = try QPeriaptHybrid.combine(profile: profile, input: hex(String(p[1])))
            XCTAssertEqual(got, hex(String(p[2])),
                           "Swift combine must match the Rust core byte-for-byte")
            n += 1
        }
        XCTAssertEqual(n, 6, "expected 6 reference vectors")
    }
}
