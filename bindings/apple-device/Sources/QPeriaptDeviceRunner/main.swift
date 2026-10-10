import Darwin
import Foundation

private enum ResultMarkerError: Error {
    case missingDocumentsDirectory
    case missingRunID
    case invalidRunID(String)
}

private func deviceRunID() throws -> String {
    guard let value = ProcessInfo.processInfo.environment["QPERIAPT_DEVICE_RUN_ID"] else {
        throw ResultMarkerError.missingRunID
    }
    let hexDigits = Set("0123456789abcdef")
    let allowed = value.allSatisfy { hexDigits.contains($0) }
    if !allowed || value.count != 32 {
        throw ResultMarkerError.invalidRunID(value)
    }
    return value
}

private func writeResultFiles(_ marker: String, resultFileRunID: String?) throws {
    let line = marker + "\n"
    guard let documentsDirectory = FileManager.default.urls(
        for: .documentDirectory,
        in: .userDomainMask
    ).first else {
        throw ResultMarkerError.missingDocumentsDirectory
    }
    let resultURL = documentsDirectory
        .appendingPathComponent("qperiapt-device-result.txt")
    try line.write(to: resultURL, atomically: true, encoding: .utf8)
    if let resultFileRunID {
        let runBoundURL = documentsDirectory
            .appendingPathComponent("qperiapt-device-result-\(resultFileRunID).txt")
        try line.write(to: runBoundURL, atomically: true, encoding: .utf8)
    }
}

private func emitMarker(_ marker: String) {
    let line = marker + "\n"
    line.withCString { ptr in
        _ = write(STDERR_FILENO, ptr, strlen(ptr))
    }
    fsync(STDERR_FILENO)
}

private func finish(_ marker: String, resultFileRunID: String?, exitCode: Int32) -> Never {
    do {
        try writeResultFiles(marker, resultFileRunID: resultFileRunID)
        emitMarker(marker)
        exit(exitCode)
    } catch {
        emitMarker("QPERIAPT_DEVICE_FAIL result-write-failed original-marker=\(marker) write-error=\(error)")
        exit(1)
    }
}

@main
struct DeviceRunner {
    static func main() async {
        do {
            let runID = try deviceRunID()
            #if QPERIAPT_SDK_DEVICE
            let tests = try await SDKDeviceSmoke.run()
            let marker = "QPERIAPT_SDK_DEVICE_PASS profile=sdk-020 version=\(SDKDeviceSmoke.version) " +
                "abi=2 extension=1 tests=\(tests.joined(separator: ",")) run-id=\(runID)"
            #else
            try DeviceSmoke.run()
            let marker = "QPERIAPT_DEVICE_PASS run-id=\(runID)"
            #endif
            finish(marker, resultFileRunID: runID, exitCode: 0)
        } catch {
            finish("QPERIAPT_DEVICE_FAIL \(error)", resultFileRunID: try? deviceRunID(), exitCode: 1)
        }
    }
}
