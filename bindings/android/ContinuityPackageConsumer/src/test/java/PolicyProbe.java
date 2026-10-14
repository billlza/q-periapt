// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Arrays;
import static dev.qperiapt.continuity.android.tests.EnrollmentProbe.*;

/** Public policy-only lifecycle over one original managed installation. */
public final class PolicyProbe {
    private PolicyProbe() { }
    static ConfigurationInputs.ProtocolPolicy document(Path inputs) throws Exception {
        return new ConfigurationInputs.ProtocolPolicy(read(inputs, "family"), read(inputs, "policy-root"),
            counter(ByteBuffer.wrap(read(inputs, "policy-version"))).toString(), read(inputs, "policy-digest"), read(inputs, "protocol-policy"));
    }
    private static AccountPin pin(Path inputs) throws Exception {
        return new AccountPin(read(inputs, "trusted-account"), read(inputs, "enrollment-root"), read(inputs, "family"),
            counter(ByteBuffer.wrap(read(inputs, "trusted-roster-version"))), read(inputs, "trusted-roster-digest"));
    }
    private static Path target(Path installation) { return Path.of(installation.toString() + ".policy-target"); }
    static void selectTarget(ContinuityEnrollment enrollment, Path inputs, Path installation, boolean recovery) throws Exception {
        try (ContinuityConfiguration configuration = configuration(inputs.resolve("policy-target"), target(installation), recovery, false)) {
            configuration.finishOpen(); configuration.selectContinuedPolicy(enrollment);
        }
    }
    private static boolean selected(String mode) {
        return JointPolicyProbe.selected(mode) || PolicyCredentialProbe.selected(mode) || mode.startsWith("policy-stage") || mode.equals("policy-reconcile") || mode.equals("policy-witness-prepare")
            || mode.equals("policy-witness-commit-unknown") || mode.equals("policy-witness-commit-replay")
            || mode.equals("policy-activate-renewed") || mode.equals("policy-activate-unmanaged") || mode.equals("policy-peer-retry");
    }
    private static void stage(ContinuityEnrollment enrollment, Path inputs, String mode, Path output) throws Exception {
        PolicyRenewalRequest request = PolicyProbeRecords.request(read(inputs, "renewal-request"));
        byte[] approvals = read(inputs, "renewal-approvals");
        if (mode.equals("policy-stage-refused")) approvals[approvals.length - 1] ^= 1;
        if (mode.equals("policy-stage-scope")) {
            PolicyRenewalScope scope = request.scope(); byte[] other = scope.operation().encoded(); other[0] ^= 1;
            PolicyRenewalScope substituted = new PolicyRenewalScope(new Ids.PolicyRenewal(other), scope.journal(), scope.originalOwner(),
                scope.originalCredential(), scope.currentCredential(), scope.currentRoster(), scope.originalPolicy(), scope.previousPolicy(), scope.previousAuthorization());
            request = new PolicyRenewalRequest(substituted, request.account(), request.originalRosterCheckpoint(),
                request.originalCredential(), request.originalRoster(), request.currentCredential(), request.currentRoster());
        }
        int expected = mode.equals("policy-stage-refused") ? 102 : mode.equals("policy-stage-scope") ? 103 : mode.equals("policy-stage-cancelled") ? 302 : 0;
        if (expected == 302) enrollment.cancel();
        AccountPin pin = pin(inputs); ConfigurationInputs.ProtocolPolicy previous = document(inputs);
        PolicyRenewalRequest retained = request;
        if (expected != 0) {
            failed(expected, () -> enrollment.stagePolicyRenewal(retained, pin, pin, approvals, previous));
            publish(output, ByteBuffer.allocate(4).putInt(expected).array());
        } else publish(output, PolicyProbeRecords.status(enrollment.stagePolicyRenewal(retained, pin, pin, approvals, previous)));
    }
    private static void run(Path inputs, Path installation, Path output, String profile, String mode, ConfigurationWitness witness) throws Exception {
        boolean recovery = profile.equals("recoverable"); require(recovery || profile.equals("fixed"), "profile");
        if (mode.equals("policy-target-create")) {
            try (ContinuityConfiguration configuration = configuration(inputs.resolve("policy-target"), target(installation), recovery, true)) {
                configuration.finishOpen();
            }
            publish(output, new byte[] {1}); return;
        }
        boolean create = mode.equals("policy-create");
        try (ContinuityConfiguration configuration = configuration(inputs, installation, recovery, create)) {
            configuration.finishOpen();
            try (ContinuityEnrollment enrollment = create ? configuration.createEnrollment(intent(inputs), witness)
                    : configuration.resumeEnrollment(intent(inputs), witness)) {
                if (create) { publish(output, enrollment.request()); return; }
                ContinuityAccountAuthority registry = null;
                try {
                    if (witness != null && !mode.equals("policy-activate-unmanaged")) {
                        registry = AuthorityProbe.open(inputs, installation);
                        enrollment.selectAccountAuthority(registry, AuthorityProbe.expected(inputs));
                    }
                    if (selected(mode)) selectTarget(enrollment, inputs, installation, recovery);
                    if (mode.startsWith("policy-joint-")) {
                        JointPolicyProbe.run(enrollment, inputs, installation, recovery, mode, output); return;
                    }
                    if (mode.startsWith("policy-credential-")) {
                        PolicyCredentialProbe.run(enrollment, inputs, mode, output, witness != null); return;
                    }
                    if (mode.startsWith("policy-stage")) { stage(enrollment, inputs, mode, output); return; }
                    if (mode.startsWith("policy-peer-")) {
                        try (ContinuityDevice device = mode.equals("policy-peer-retry") ? enrollment.activatePolicyRenewal() : enrollment.activate()) {
                            if (mode.equals("policy-peer-unassociated")) PeerProbe.unassociated(device, inputs, output);
                            else PeerProbe.client(device, inputs, mode.substring("policy-".length()), output);
                        }
                        return;
                    }
                    switch (mode) {
                        case "policy-prepare" -> {
                            byte[] journal = enrollment.accept(read(inputs, "grant-certificate"), read(inputs, "grant-roster"), pin(inputs));
                            StoragePreparation prepared = enrollment.prepareStorage();
                            require(Arrays.equals(journal, prepared.journalId()) && prepared.requiresWitnessEnrollment() == (witness != null), "original storage protection");
                            ByteBuffer bytes = ByteBuffer.allocate(164).putInt(witness == null ? 1 : 2).put(journal);
                            if (witness != null) bytes.put(prepared.witnessSubject()).put(prepared.imageDigest());
                            publish(output, bytes.array());
                        }
                        case "policy-activate" -> {
                            byte[] original = enrollment.request(); try (ContinuityDevice device = enrollment.activate()) { device.cancel(); }
                            publish(output, original);
                        }
                        case "policy-activate-expired", "policy-activate-unmanaged" -> {
                            int code = mode.equals("policy-activate-expired") ? 104 : 211;
                            if (code == 104) failed(code, enrollment::activate); else failed(code, enrollment::activatePolicyRenewal);
                            publish(output, ByteBuffer.allocate(4).putInt(code).array());
                        }
                        case "policy-activate-unselected" -> {
                            failed(1, enrollment::activatePolicyRenewal); publish(output, ByteBuffer.allocate(4).putInt(1).array());
                        }
                        case "policy-identity" -> publish(output, CredentialProbe.identity(enrollment));
                        case "policy-request" -> {
                            Ids.PolicyRenewal operation = new Ids.PolicyRenewal(read(inputs, "renewal-operation"));
                            publish(output, PolicyProbeRecords.request(witness == null ? enrollment.policyRenewalRequest(operation) : enrollment.witnessedPolicyRenewalRequest(operation)));
                        }
                        case "policy-status" -> publish(output, PolicyProbeRecords.status(enrollment.policyRenewalStatus()));
                        case "policy-approval" -> publish(output, enrollment.pendingPolicyRenewalApproval(new Ids.PolicyRenewal(read(inputs, "renewal-operation"))));
                        case "policy-reconcile" -> publish(output, PolicyProbeRecords.status(enrollment.reconcilePolicyRenewal()));
                        case "policy-resolve" -> {
                            Ids.PolicyRenewal operation = new Ids.PolicyRenewal(read(inputs, "renewal-operation"));
                            Ids.PolicyStatement statement = new Ids.PolicyStatement(read(inputs, "renewal-statement"));
                            ConfigurationInputs.ProtocolPolicy target = document(inputs.resolve("policy-target"));
                            if (witness != null) {
                                failed(216, () -> enrollment.resolvePolicyRenewal(operation, statement, target));
                                publish(output, ByteBuffer.allocate(4).putInt(216).array());
                            } else publish(output, PolicyProbeRecords.status(enrollment.resolvePolicyRenewal(operation, statement, target)));
                        }
                        case "policy-witness-prepare" -> publish(output, enrollment.prepareWitnessedPolicyRenewal(document(inputs)).encoded());
                        case "policy-witness-recover" -> {
                            IndependentPolicyProposal proposal = enrollment.recoverWitnessedPolicyRenewalPreparation(); require(proposal != null, "original proposal missing"); publish(output, proposal.encoded());
                        }
                        case "policy-progress" -> publish(output, PolicyProbeRecords.progress(enrollment.witnessedPolicyRenewalProgress()));
                        case "policy-witness-commit-unknown" -> {
                            IndependentPolicyProposal proposal = new IndependentPolicyProposal(read(inputs, "renewal-proposal"));
                            failed(218, () -> enrollment.commitWitnessedPolicyRenewal(proposal)); publish(output, ByteBuffer.allocate(4).putInt(218).array());
                        }
                        case "policy-witness-reconcile", "policy-witness-close", "policy-witness-commit-replay" -> {
                            IndependentPolicyProposal proposal = new IndependentPolicyProposal(read(inputs, "renewal-proposal"));
                            IndependentPolicyState state = mode.equals("policy-witness-close") ? enrollment.closeWitnessedPolicyRenewal(proposal)
                                : mode.equals("policy-witness-commit-replay") ? enrollment.commitWitnessedPolicyRenewal(proposal) : enrollment.reconcileWitnessedPolicyRenewal(proposal);
                            publish(output, ByteBuffer.allocate(4).putInt(state.ordinal() + 1).array());
                        }
                        case "policy-activate-renewed" -> {
                            byte[] original = CredentialProbe.identity(enrollment);
                            try (ContinuityDevice device = enrollment.activatePolicyRenewal()) { device.cancel(); }
                            publish(output, original);
                        }
                        default -> throw new IllegalArgumentException("policy operation");
                    }
                } finally { if (registry != null) registry.close(); }
            }
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("inputs installation profile mode result");
        Path inputs = Path.of(args[0]), installation = Path.of(args[1]), output = Path.of(args[4]);
        if (new String(read(inputs, "witness-carrier"), java.nio.charset.StandardCharsets.US_ASCII).equals("local"))
            run(inputs, installation, output, args[2], args[3], null);
        else WitnessProbe.withWitness(inputs, args[3], witness -> run(inputs, installation, output, args[2], args[3], witness));
        System.out.println(args[2] + ":" + args[3] + ":passed");
    }
}
