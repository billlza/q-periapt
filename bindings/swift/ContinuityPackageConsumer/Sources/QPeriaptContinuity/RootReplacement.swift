// SPDX-License-Identifier: Apache-2.0 OR MIT
import CQPCOwner
import Foundation

private func rootProposal(_ call: (UnsafeMutablePointer<UInt8>?, Int, UnsafeMutablePointer<Int>,
                                  UnsafeMutablePointer<qpc_error_v1>) -> Int32) throws -> RootReplacementProposal {
    var bytes = [UInt8](repeating: 0, count: 65536), written = 0, error = qpc_error_v1()
    let code = bytes.withUnsafeMutableBufferPointer { call($0.baseAddress, $0.count, &written, &error) }
    try checked(code, &error)
    guard (8...bytes.count).contains(written) else { throw ContinuityBoundaryError.malformedOutput }
    return try RootReplacementProposal.decode(Array(bytes.prefix(written)))
}

extension ContinuityAccountAuthority {
    /// Turn this registry into the original root controller. The old device and
    /// its aliases lose operation authority. Keep this owner alive through cleanup
    /// and successor use; close/final release revokes its selected successor.
    public func beginRootReplacement(device: ContinuityDevice, scope: RootReplacementScope,
                                     plan: RootReplacementPlan) throws {
        try native.call { registry in try device.call { device in
            try scope.withNative { scope in try plan.bytes.withUnsafeBufferPointer { plan in
                var error = qpc_error_v1()
                try checked(qpc_root_v1_begin(registry, device, scope, plan.baseAddress, plan.count, &error), &error)
            } }
        } }
    }
    /// Reopen the exact original registry and enrollment; missing state is an
    /// error. A previously selected transition/adoption needs its matching resume.
    public func resumeRootReplacement(path: String, intent: EnrollmentIntent,
                                      scope: RootReplacementScope, plan: RootReplacementPlan) throws {
        let path = try textBytes(path, maximum: 4096)
        try native.call { registry in try intent.withNative { intent in try scope.withNative { scope in
            try path.withUnsafeBufferPointer { path in try plan.bytes.withUnsafeBufferPointer { plan in
                var error = qpc_error_v1()
                try checked(qpc_root_v1_resume(registry, path.baseAddress, path.count, intent, scope,
                    plan.baseAddress, plan.count, &error), &error)
            } }
        } } }
    }
    public func rootReplacementState() throws -> RootReplacementState {
        try native.call { registry in
            var state: UInt32 = 0, error = qpc_error_v1()
            try checked(qpc_root_v1_state(registry, &state, &error), &error)
            guard let state = RootReplacementState(rawValue: state) else { throw ContinuityBoundaryError.malformedOutput }
            return state
        }
    }
    public func bindRootFreeze(receipt: [UInt8]) throws -> RootReplacementProposal {
        guard (1...131072).contains(receipt.count) else { throw ContinuityBoundaryError.inputLength }
        return try native.call { registry in try receipt.withUnsafeBufferPointer { receipt in
            try rootProposal { qpc_root_v1_bind_freeze(registry, receipt.baseAddress, receipt.count, $0, $1, $2, $3) }
        } }
    }
    public func retainRootRetirement(receipt: [UInt8]) throws -> AccountAuthorityCheckpoint {
        guard receipt.count == 3449 else { throw ContinuityBoundaryError.inputLength }
        return try native.call { registry in try receipt.withUnsafeBufferPointer { receipt in
            var value = qpc_authority_checkpoint_v1(), error = qpc_error_v1()
            try checked(qpc_root_v1_retain_retirement(registry, receipt.baseAddress, receipt.count, &value, &error), &error)
            return try accountAuthorityCheckpoint(&value)
        } }
    }
    /// Signed permanent noncommit retains the original root suspension; it does
    /// not unfreeze it or independently authorize another target.
    public func retainRootNoncommit(receipt: [UInt8]) throws -> RootReplacementState {
        guard receipt.count == 3449 else { throw ContinuityBoundaryError.inputLength }
        return try native.call { registry in try receipt.withUnsafeBufferPointer { receipt in
            var value: UInt32 = 0, error = qpc_error_v1()
            try checked(qpc_root_v1_retain_noncommit(registry, receipt.baseAddress, receipt.count, &value, &error), &error)
            guard let state = RootReplacementState(rawValue: value) else { throw ContinuityBoundaryError.malformedOutput }
            return state
        } }
    }
    /// Activate only with current successor credentials/policy/witness authority.
    /// Unknown results may consume both owners; close and resume the same inputs.
    public func activateRootSuccessor(_ enrollment: ContinuityEnrollment) throws -> ContinuityDevice {
        try native.call { try enrollment.activateRootSuccessor(registry: $0) }
    }
    public func transitionRoot(_ approval: RootReplacementTransition) throws -> RootReplacementProposal {
        try native.call { registry in try approval.inputs.withNative { approval in
            try rootProposal { qpc_root_v1_transition(registry, approval, $0, $1, $2, $3) }
        } }
    }
    public func adoptRoot(_ approval: RootReplacementAdoption) throws -> AccountAuthorityCheckpoint {
        try native.call { registry in try approval.inputs.withNative { approval in
            var value = qpc_authority_checkpoint_v1(), error = qpc_error_v1()
            try checked(qpc_root_v1_adopt(registry, approval, &value, &error), &error)
            return try accountAuthorityCheckpoint(&value)
        } }
    }
    public func resumeRootTransition(path: String, intent: EnrollmentIntent, scope: RootReplacementScope,
                                     approval: RootReplacementTransition) throws {
        try resumeRootAlternative(path: path, intent: intent, scope: scope, inputs: approval.inputs,
            invoke: qpc_root_v1_resume_transition)
    }
    public func resumeRootAdoption(path: String, intent: EnrollmentIntent, scope: RootReplacementScope,
                                   approval: RootReplacementAdoption) throws {
        try resumeRootAlternative(path: path, intent: intent, scope: scope, inputs: approval.inputs,
            invoke: qpc_root_v1_resume_adoption)
    }
    private func resumeRootAlternative(path: String, intent: EnrollmentIntent, scope: RootReplacementScope,
        inputs: RootAlternativeInputs, invoke: (UInt64, UnsafePointer<UInt8>?, Int,
            UnsafePointer<qpc_enrollment_intent_v1>?, UnsafePointer<qpc_root_scope_v1>?,
            UnsafePointer<qpc_root_alternative_v1>?, UnsafeMutablePointer<qpc_error_v1>?) -> Int32) throws {
        let path = try textBytes(path, maximum: 4096)
        try native.call { registry in try intent.withNative { intent in try scope.withNative { scope in
            try inputs.withNative { approval in try path.withUnsafeBufferPointer { path in
                var error = qpc_error_v1()
                try checked(invoke(registry, path.baseAddress, path.count, intent, scope, approval, &error), &error)
            } }
        } } }
    }
}
