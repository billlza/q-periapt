// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Actual original-operation renewal, with historical cleanup separate from fresh activation. */
public final class CredentialProbe {
    private CredentialProbe() { }
    private static byte[] status(CredentialRenewalStatus value) {
        ByteBuffer output = ByteBuffer.allocate(116); output.putInt(value.phase().ordinal());
        if (value.operation() != null) { output.put(value.operation().encoded()); output.put(value.statement().encoded()); }
        output.position(68);
        if (value.checkpoint() != null) { output.putLong(Long.parseUnsignedLong(value.checkpoint().version().toString())); output.put(value.checkpoint().digest()); }
        output.position(108); if (value.observedAt() != null) output.putLong(Long.parseUnsignedLong(value.observedAt().toString()));
        return output.array();
    }
    private static byte[] identity(ContinuityEnrollment enrollment) {
        EnrollmentStatus observed = enrollment.status();
        require(observed.journalId() != null, "original journal is absent");
        return ByteBuffer.allocate(64).put(observed.signingKeyId()).put(observed.journalId()).array();
    }
    private static void run(Path inputs, Path installation, Path output, String profile, String mode, ConfigurationWitness witness) throws Exception {
        boolean recovery = profile.equals("recoverable"); require(recovery || profile.equals("fixed"), "profile");
        boolean historical = mode.equals("credential-reconcile") || mode.equals("credential-commit-replay")
            || mode.equals("credential-commit-unmanaged") || mode.equals("credential-activate-unmanaged");
        try (ContinuityConfiguration configuration = configuration(inputs, installation, recovery, false)) {
            configuration.finishOpen();
            try (ContinuityEnrollment enrollment = configuration.resumeEnrollment(intent(inputs), witness)) {
                ContinuityAccountAuthority registry = null;
                try {
                    if (!historical) {
                        registry = AuthorityProbe.open(inputs, installation);
                        enrollment.selectAccountAuthority(registry, AuthorityProbe.expected(inputs));
                    }
                    if (mode.equals("credential-identity")) { publish(output, identity(enrollment)); return; }
                    if (mode.equals("credential-status")) { publish(output, status(enrollment.credentialRenewalStatus())); return; }
                    if (mode.startsWith("credential-peer-")) {
                        try (ContinuityDevice active = enrollment.activate()) {
                            if (mode.equals("credential-peer-unassociated")) PeerProbe.unassociated(active, inputs, output);
                            else PeerProbe.client(active, inputs, mode.substring("credential-".length()), output);
                        }
                        return;
                    }
                    Ids.CredentialRenewal operation = new Ids.CredentialRenewal(read(inputs, "credential-operation"));
                    Ids.CredentialStatement statement = new Ids.CredentialStatement(read(inputs, "credential-statement"));
                    switch (mode) {
                        case "credential-stage", "credential-stage-refused" -> {
                            AccountPin pin = new AccountPin(read(inputs, "trusted-account"), read(inputs, "enrollment-root"), read(inputs, "family"),
                                counter(ByteBuffer.wrap(read(inputs, "renewal-version"))), read(inputs, "renewal-digest"));
                            byte[] grant = read(inputs, "credential-renewal");
                            if (mode.equals("credential-stage-refused")) {
                                grant[grant.length - 1] ^= 1;
                                failed(102, () -> enrollment.stageCredentialRenewal(grant, pin, operation));
                                publish(output, ByteBuffer.allocate(4).putInt(102).array());
                            } else publish(output, status(enrollment.stageCredentialRenewal(grant, pin, operation)));
                        }
                        case "credential-prepare" -> {
                            CredentialRenewalProposal proposal = enrollment.prepareWitnessedCredentialRenewal();
                            require(proposal.operation().equals(operation) && proposal.statement().equals(statement), "original proposal scope");
                            publish(output, proposal.encoded());
                        }
                        case "credential-commit-closed" -> {
                            require(registry != null, "selected registry"); registry.close(); registry = null;
                            failed(202, () -> enrollment.commitWitnessedCredentialRenewal(operation, statement));
                            publish(output, ByteBuffer.allocate(4).putInt(202).array());
                        }
                        case "credential-commit-unmanaged", "credential-commit-unknown" -> {
                            int code = mode.equals("credential-commit-unmanaged") ? 211 : 218;
                            failed(code, () -> enrollment.commitWitnessedCredentialRenewal(operation, statement));
                            publish(output, ByteBuffer.allocate(4).putInt(code).array());
                        }
                        case "credential-reconcile" -> publish(output, status(enrollment.reconcileWitnessedCredentialRenewal(operation, statement)));
                        case "credential-commit-replay" -> publish(output, status(enrollment.commitWitnessedCredentialRenewal(operation, statement)));
                        case "credential-activate-unmanaged" -> {
                            failed(211, enrollment::activate); publish(output, ByteBuffer.allocate(4).putInt(211).array());
                        }
                        case "credential-activate" -> {
                            byte[] original = identity(enrollment);
                            try (ContinuityDevice active = enrollment.activate()) { active.cancel(); }
                            publish(output, original);
                        }
                        default -> throw new IllegalArgumentException("credential operation");
                    }
                } finally { if (registry != null) registry.close(); }
            }
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("inputs installation profile mode result");
        Path inputs = Path.of(args[0]), installation = Path.of(args[1]), output = Path.of(args[4]);
        WitnessProbe.withWitness(inputs, args[3], witness -> run(inputs, installation, output, args[2], args[3], witness));
        System.out.println(args[2] + ":" + args[3] + ":passed");
    }
}
