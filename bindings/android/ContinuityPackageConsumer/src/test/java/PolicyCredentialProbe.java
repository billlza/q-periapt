// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** G after independently committed P, through the original public enrollment owner. */
final class PolicyCredentialProbe {
    private PolicyCredentialProbe() { }
    static boolean selected(String mode) {
        return mode.equals("policy-credential-stage") || mode.equals("policy-credential-stage-refused")
            || mode.equals("policy-credential-prepare") || mode.equals("policy-credential-commit-unknown")
            || mode.equals("policy-credential-commit") || mode.equals("policy-credential-local");
    }
    private static long bits(Counter64 value) { return Long.parseUnsignedLong(value.toString()); }
    private static void record(ByteBuffer out, byte[] value) {
        require(value.length > 0 && value.length <= 8192, "credential request public record");
        out.putInt(value.length).put(value); out.position(out.position() + 8192 - value.length);
    }
    private static void roster(ByteBuffer out, RosterCheckpoint value) { out.putLong(bits(value.version())).put(value.digest()); }
    /** Test interchange built only from public getters, not native memory or fixture credentials. */
    private static byte[] request(CredentialRenewalRequest value) {
        ByteBuffer out = ByteBuffer.allocate(33120);
        out.put(value.operation().encoded()).put(value.journal().encoded()).put(value.originalOwner()).put(value.originalPolicyDigest());
        out.putLong(bits(value.currentPolicy().version())).put(value.currentPolicy().digest());
        out.put(value.currentPolicyAuthorization() == null ? new byte[32] : value.currentPolicyAuthorization().encoded());
        out.putInt(value.currentPolicyAuthorization() == null ? 0 : 1).putInt(0);
        roster(out, value.previousRosterCheckpoint()); roster(out, value.originalRosterCheckpoint());
        out.putLong(bits(value.previousValidFrom())).putLong(bits(value.previousValidUntil())).put(value.account().encoded());
        record(out, value.originalCredential()); record(out, value.originalRoster());
        record(out, value.previousCredential()); record(out, value.previousRoster());
        require(!out.hasRemaining(), "credential request complete"); return out.array();
    }
    static void run(ContinuityEnrollment enrollment, Path inputs, String mode, Path output, boolean witnessed) throws Exception {
        Ids.CredentialRenewal operation = new Ids.CredentialRenewal(read(inputs, mode.equals("policy-credential-next-request") ? "credential-next-operation" : "credential-operation"));
        if (mode.equals("policy-credential-request") || mode.equals("policy-credential-next-request")) {
            publish(output, request(witnessed ? enrollment.witnessedCredentialRenewalRequest(operation) : enrollment.credentialRenewalRequest(operation)));
            return;
        }
        if (mode.equals("policy-credential-request-local-refused")) {
            failed(216, () -> enrollment.credentialRenewalRequest(operation)); publish(output, ByteBuffer.allocate(4).putInt(216).array()); return;
        }
        Ids.CredentialStatement statement = new Ids.CredentialStatement(read(inputs, "credential-statement"));
        switch (mode) {
            case "policy-credential-stage", "policy-credential-stage-refused" -> {
                AccountPin pin = new AccountPin(read(inputs, "trusted-account"), read(inputs, "enrollment-root"), read(inputs, "family"),
                    counter(ByteBuffer.wrap(read(inputs, "renewal-version"))), read(inputs, "renewal-digest"));
                byte[] grant = read(inputs, "credential-renewal");
                if (mode.endsWith("-refused")) {
                    grant[grant.length - 1] ^= 1;
                    failed(102, () -> enrollment.stageContinuedCredentialRenewal(grant, pin, operation));
                    publish(output, ByteBuffer.allocate(4).putInt(102).array());
                } else publish(output, CredentialProbe.status(enrollment.stageContinuedCredentialRenewal(grant, pin, operation)));
            }
            case "policy-credential-prepare" -> {
                PolicyRenewalProposal proposal = enrollment.prepareWitnessedPolicyContinuation();
                require(proposal.operation().equals(operation) && proposal.credentialStatement().equals(statement)
                    && proposal.policyStatement() == null && !proposal.adoptsPolicy()
                    && proposal.independentPolicyStatement().equals(new Ids.PolicyStatement(read(inputs, "renewal-statement"))), "G retains independently applied P");
                publish(output, proposal.encoded());
            }
            case "policy-credential-commit-unknown" -> {
                failed(218, () -> enrollment.commitWitnessedPolicyContinuation(operation, statement));
                publish(output, ByteBuffer.allocate(4).putInt(218).array());
            }
            case "policy-credential-commit" -> publish(output, CredentialProbe.status(enrollment.commitWitnessedPolicyContinuation(operation, statement)));
            case "policy-credential-local" -> {
                byte[] identity = CredentialProbe.identity(enrollment);
                try (ContinuityDevice active = enrollment.activatePolicyRenewal()) { active.cancel(); }
                publish(output, identity);
            }
            case "policy-credential-reconcile" -> publish(output, CredentialProbe.status(enrollment.reconcileWitnessedCredentialRenewal(operation, statement)));
            case "policy-credential-close" -> publish(output, CredentialProbe.status(enrollment.closeWitnessedCredentialRenewal(operation, statement)));
            case "policy-credential-status" -> publish(output, CredentialProbe.status(enrollment.credentialRenewalStatus()));
            default -> throw new IllegalArgumentException("policy credential operation");
        }
    }
}
