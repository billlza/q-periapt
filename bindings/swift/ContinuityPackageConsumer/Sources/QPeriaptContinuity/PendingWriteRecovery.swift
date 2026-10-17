// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

/// Complete original public request. Retain all fields before independent approval.
/// Metadata contains private account/device linkage; these bytes grant no authority.
public struct PendingWriteRecoveryRequest: Sendable, Equatable {
    public let proposal: [UInt8]
    public let binding: [UInt8]
    public let metadata: [UInt8]
    public let signedRequest: [UInt8]

    init(proposal: [UInt8], binding: [UInt8], metadata: [UInt8], signedRequest: [UInt8]) throws {
        guard binding.count == 32, (1...8192).contains(signedRequest.count),
              pendingWriteShape(proposal: proposal, metadata: metadata) else {
            throw ContinuityBoundaryError.malformedOutput
        }
        self.proposal = proposal; self.binding = binding
        self.metadata = metadata; self.signedRequest = signedRequest
    }
}

// Shape only: native code authenticates the full metadata, original lineage and
// fresh signed witness response. Length arithmetic is bounded before indexing.
func pendingWriteShape(proposal: [UInt8], metadata: [UInt8]) -> Bool {
    guard proposal.count == 393, Array(proposal.prefix(8)) == Array("QPWRPL01".utf8),
          (569...8388608).contains(metadata.count), Array(metadata.prefix(8)) == Array("QPWRMD01".utf8),
          proposal[8..<361].elementsEqual(metadata[8..<361]) else { return false }
    var offset = 361
    for _ in 0..<2 {
        guard metadata.count - offset >= 8 else { return false }
        var length: UInt64 = 0
        for byte in metadata[offset..<(offset + 8)] { length = (length << 8) | UInt64(byte) }
        offset += 8
        guard length >= 96, length <= UInt64(metadata.count - offset) else { return false }
        offset += Int(length)
    }
    return offset == metadata.count
}

struct PendingWriteRecoveryOperations: Sendable {
    let native: NativeOwner
    func request() throws -> PendingWriteRecoveryRequest {
        try native.call { handle in
            var info = qpc_pending_write_request_info_v1(), error = qpc_error_v1()
            try checked(qpc_enrollment_v1_pending_write_request(handle, &info, &error), &error)
            guard (569...8388608).contains(info.metadata_length), (1...8192).contains(info.signed_request_length),
                  octets(info.reserved_zero).allSatisfy({ $0 == 0 }) else {
                throw ContinuityBoundaryError.malformedOutput
            }
            let proposal = octets(info.proposal), binding = octets(info.binding)
            var metadata = [UInt8](repeating: 0, count: Int(info.metadata_length))
            var signed = [UInt8](repeating: 0, count: Int(info.signed_request_length))
            let code = binding.withUnsafeBufferPointer { expected in
                metadata.withUnsafeMutableBufferPointer { document in
                    signed.withUnsafeMutableBufferPointer { request in
                        qpc_enrollment_v1_copy_pending_write_request(handle, expected.baseAddress,
                            document.baseAddress, document.count, request.baseAddress, request.count, &error)
                    }
                }
            }
            try checked(code, &error)
            return try PendingWriteRecoveryRequest(proposal: proposal, binding: binding, metadata: metadata, signedRequest: signed)
        }
    }
    func confirm(approved: [UInt8], recordedMetadata: [UInt8]) throws {
        guard approved.count == 393, (1...8388608).contains(recordedMetadata.count) else {
            throw ContinuityBoundaryError.inputLength
        }
        try native.call { handle in
            var error = qpc_error_v1()
            let code = approved.withUnsafeBufferPointer { proposal in
                recordedMetadata.withUnsafeBufferPointer { metadata in
                    qpc_enrollment_v1_confirm_pending_write_recovery(handle, proposal.baseAddress, proposal.count,
                        metadata.baseAddress, metadata.count, &error)
                }
            }
            try checked(code, &error)
        }
    }
}
