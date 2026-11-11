// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Required-witness G/T operations through public owned Android APIs. */
final class JointWitnessProbe {
    private JointWitnessProbe() { }
    static boolean selected(String mode) {
        return mode.equals("policy-joint-witness-prepare") || mode.equals("policy-joint-witness-commit-unknown")
            || mode.equals("policy-joint-witness-local-refused") || mode.equals("policy-joint-witness-reserved-commit-refused")
            || mode.equals("policy-joint-witness-reserved-activate-refused");
    }
    static void run(ContinuityEnrollment owner, Path inputs, String mode, Path output) throws Exception {
        Ids.CredentialRenewal operation = new Ids.CredentialRenewal(read(inputs, "credential-operation"));
        Ids.CredentialStatement statement = new Ids.CredentialStatement(read(inputs, "credential-statement"));
        switch (mode) {
            case "policy-joint-witness-prepare", "policy-joint-witness-recover" -> {
                PolicyRenewalProposal proposal = owner.prepareWitnessedPolicyContinuation();
                require(proposal.operation().equals(operation) && proposal.statement().equals(statement)
                    && !proposal.credentialStatement().equals(statement) && proposal.adoptsPolicy()
                    && proposal.policyStatement().equals(new Ids.PolicyContinuationStatement(statement.encoded()))
                    && proposal.independentPolicyStatement() == null, "joint T proposal domain");
                publish(output, proposal.encoded());
            }
            case "policy-joint-witness-cancel-prepare" -> {
                PolicyRenewalCancellation cancellation = owner.prepareWitnessedPolicyCancellation();
                require(cancellation.operation().equals(operation) && cancellation.statement().equals(statement)
                    && !cancellation.credentialStatement().equals(statement) && cancellation.adoptsPolicy()
                    && cancellation.policyStatement().equals(new Ids.PolicyContinuationStatement(statement.encoded()))
                    && cancellation.independentPolicyStatement() == null, "joint T cancellation domain");
                publish(output, cancellation.encoded());
            }
            case "policy-joint-witness-local-refused" -> {
                failed(216, owner::reconcilePolicyContinuation); publish(output, ByteBuffer.allocate(4).putInt(216).array());
            }
            case "policy-joint-witness-history-local-refused" -> {
                ConfigurationInputs.ProtocolPolicy target = PolicyProbe.document(inputs.resolve("policy-target"));
                failed(216, () -> owner.recoverHistoricalPolicyContinuation(operation, statement, target));
                publish(output, ByteBuffer.allocate(4).putInt(216).array());
            }
            case "policy-joint-witness-commit-unknown", "policy-joint-witness-reserved-commit-refused" -> {
                int code = mode.endsWith("-unknown") ? 218 : 215;
                failed(code, () -> owner.commitWitnessedPolicyContinuation(operation, statement));
                publish(output, ByteBuffer.allocate(4).putInt(code).array());
            }
            case "policy-joint-witness-reserved-activate-refused" -> {
                failed(215, owner::activatePolicyContinuation); publish(output, ByteBuffer.allocate(4).putInt(215).array());
            }
            case "policy-joint-witness-commit-replay" -> publish(output, CredentialProbe.status(owner.commitWitnessedPolicyContinuation(operation, statement)));
            case "policy-joint-witness-reconcile" -> publish(output, CredentialProbe.status(owner.reconcileWitnessedCredentialRenewal(operation, statement)));
            case "policy-joint-witness-close" -> publish(output, CredentialProbe.status(owner.closeWitnessedCredentialRenewal(operation, statement)));
            default -> throw new IllegalArgumentException("joint witness operation");
        }
    }
}
