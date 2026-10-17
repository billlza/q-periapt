// SPDX-License-Identifier: Apache-2.0 OR MIT
import Foundation

/// Executes the device workload on macOS without producing a device marker.
@main
struct HostProbe {
    static func main() async throws {
        guard CommandLine.arguments.count == 2,
              let bundle = Bundle(path: CommandLine.arguments[1]) else {
            throw DeviceSmokeError.invalidVector("host fixture bundle")
        }
        let tests = try await SDKDeviceSmoke.run(resources: bundle)
        print("HOST_SDK_DEVICE_SUITE_PASS tests=\(tests.joined(separator: ","))")
    }
}
