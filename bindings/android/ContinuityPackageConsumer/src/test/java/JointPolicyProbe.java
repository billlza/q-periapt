// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Joint G/T through public Android owners; each invocation is a separate process. */
final class JointPolicyProbe {
    private JointPolicyProbe() { }
    static boolean selected(String mode) {
        return mode.startsWith("policy-joint-stage") || mode.equals("policy-joint-reconcile")
            || mode.equals("policy-joint-activate") || mode.equals("policy-joint-peer-retry")
            || JointWitnessProbe.selected(mode);
    }
    static void run(ContinuityEnrollment owner, Path inputs, Path installation, boolean recovery,
            String mode, Path output, boolean witnessed) throws Exception {
        Ids.CredentialRenewal operation = new Ids.CredentialRenewal(read(inputs, "credential-operation"));
        if (mode.equals("policy-joint-request") || mode.equals("policy-joint-next-request")) {
            // Reuse the public getter serializer, with the same original credential operation.
            PolicyCredentialProbe.run(owner, inputs, mode.equals("policy-joint-next-request")
                ? "policy-credential-next-request" : "policy-credential-request", output, witnessed); return;
        }
        if (mode.equals("policy-joint-request-local-refused")) {
            failed(216, () -> owner.credentialRenewalRequest(operation));
            publish(output, ByteBuffer.allocate(4).putInt(216).array()); return;
        }
        if (mode.startsWith("policy-joint-witness-")) { JointWitnessProbe.run(owner, inputs, mode, output); return; }
        Ids.CredentialStatement statement = new Ids.CredentialStatement(read(inputs, "credential-statement"));
        switch (mode) {
            case "policy-joint-request-reused" -> {
                failed(211, () -> {
                    if (witnessed) owner.witnessedCredentialRenewalRequest(operation); else owner.credentialRenewalRequest(operation);
                });
                publish(output, ByteBuffer.allocate(4).putInt(211).array());
            }
            case "policy-joint-stage", "policy-joint-stage-refused", "policy-joint-stage-predecessor" -> {
                AccountPin pin = new AccountPin(read(inputs, "trusted-account"), read(inputs, "enrollment-root"), read(inputs, "family"),
                    counter(ByteBuffer.wrap(read(inputs, "renewal-version"))), read(inputs, "renewal-digest"));
                byte[] approvals = read(inputs, "joint-approvals");
                if (mode.endsWith("-refused")) approvals[approvals.length - 1] ^= 1;
                ConfigurationInputs.ProtocolPolicy previous = PolicyProbe.document(inputs);
                Ids.PolicyContinuationStatement predecessor = mode.endsWith("-predecessor")
                    ? new Ids.PolicyContinuationStatement(statement.encoded()) : null;
                int expected = mode.endsWith("-refused") ? 102 : predecessor != null ? 105 : 0;
                byte[] grant = read(inputs, "credential-renewal");
                if (expected != 0) {
                    failed(expected, () -> owner.stagePolicyContinuation(grant, pin, operation, approvals, previous, predecessor));
                    publish(output, ByteBuffer.allocate(4).putInt(expected).array());
                } else publish(output, CredentialProbe.status(owner.stagePolicyContinuation(grant, pin, operation, approvals, previous, null)));
            }
            case "policy-joint-status" -> publish(output, CredentialProbe.status(owner.credentialRenewalStatus()));
            case "policy-joint-reconcile" -> publish(output, CredentialProbe.status(owner.reconcilePolicyContinuation()));
            case "policy-joint-history", "policy-joint-history-pending" -> {
                ConfigurationInputs.ProtocolPolicy target = PolicyProbe.document(inputs.resolve("policy-target"));
                if (mode.endsWith("-pending")) {
                    failed(215, () -> owner.recoverHistoricalPolicyContinuation(operation, statement, target));
                    failed(2, owner::status);
                    publish(output, ByteBuffer.allocate(4).putInt(215).array());
                } else publish(output, CredentialProbe.status(owner.recoverHistoricalPolicyContinuation(operation, statement, target)));
            }
            case "policy-joint-activate" -> {
                byte[] identity = CredentialProbe.identity(owner);
                try (ContinuityDevice device = owner.activatePolicyContinuation()) {
                    failed(2, owner::status); failed(2, owner::activatePolicyContinuation); device.cancel();
                }
                publish(output, identity);
            }
            case "policy-joint-current-expired" -> {
                try { PolicyProbe.selectTarget(owner, inputs, installation, recovery); }
                catch (ContinuityFailure failure) {
                    require(failure.code() == 104, "expired target rejection");
                    publish(output, ByteBuffer.allocate(4).putInt(104).array()); return;
                }
                throw new AssertionError("expired joint target selected");
            }
            case "policy-joint-unselected" -> {
                failed(1, owner::activatePolicyContinuation); publish(output, ByteBuffer.allocate(4).putInt(1).array());
            }
            case "policy-joint-peer-retry" -> {
                try (ContinuityDevice device = owner.activatePolicyContinuation()) { PeerProbe.client(device, inputs, "peer-retry", output); }
            }
            default -> throw new IllegalArgumentException("joint policy operation");
        }
    }
}
