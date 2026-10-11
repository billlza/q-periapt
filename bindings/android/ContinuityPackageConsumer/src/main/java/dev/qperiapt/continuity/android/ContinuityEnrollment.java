// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/** Original native enrollment; failed operations never authorize a replacement identity. */
public final class ContinuityEnrollment implements AutoCloseable {
    private final Owner owner;
    ContinuityEnrollment(long handle) { owner = new Owner(handle); }
    public void cancel() { owner.action(2); }
    @Override public void close() { owner.close(); }
    public EnrollmentStatus status() { return owner.call(false, handle -> new EnrollmentStatus(Native.enrollmentQuery(handle, 1))); }
    public byte[] request() {
        return owner.call(false, handle -> {
            byte[] wire = Native.enrollmentQuery(handle, 2);
            if (wire.length != 8196) throw new IllegalStateException("native request width");
            int length = ByteBuffer.wrap(wire).getInt();
            if (length < 1 || length > 8192) throw new IllegalStateException("native request length");
            for (int i = 4 + length; i < wire.length; ++i) if (wire[i] != 0) throw new IllegalStateException("native request tail");
            return Arrays.copyOfRange(wire, 4, 4 + length);
        });
    }
    public byte[] accept(byte[] certificate, byte[] roster, AccountPin independentPin) {
        Objects.requireNonNull(independentPin, "independent account pin");
        byte[][] pin = independentPin.snapshot();
        byte[][] inputs = {ConfigurationInputs.copy(certificate, 1, 8192, "certificate"),
            ConfigurationInputs.copy(roster, 1, 8192, "roster"), pin[0], pin[1], pin[2], pin[3]};
        return owner.call(false, handle -> {
            byte[] id = Native.enrollmentAccept(handle, inputs, independentPin.version.bits);
            if (id.length != 32 || !EnrollmentIntent.nonzero(id)) throw new IllegalStateException("native journal identity");
            return id;
        });
    }
    public StoragePreparation prepareStorage() {
        return owner.call(false, handle -> new StoragePreparation(Native.enrollmentQuery(handle, 3)));
    }
    /** Select the original live registry after independent approval of this request.
     * Keep the registry open throughout activation and use of its managed children.
     */
    public void selectAccountAuthority(ContinuityAccountAuthority registry, AccountAuthorityCheckpoint checkpoint) {
        Objects.requireNonNull(registry, "account registry").select(owner, Objects.requireNonNull(checkpoint, "checkpoint"));
    }
    /** Passive original-operation history; no current traffic permission is implied. */
    public CredentialRenewalStatus credentialRenewalStatus() {
        return owner.call(false, handle -> new CredentialRenewalStatus(Native.credentialCommand(handle, 1, new byte[0][], 0)));
    }
    /** Stage an independently approved same-key grant under the original policy.
     * Close active devices first. Required-witness protection needs its explicit
     * prepare/terminal workflow before the ordinary consuming activate call.
     */
    public CredentialRenewalStatus stageCredentialRenewal(byte[] grant, AccountPin independentPin, Ids.CredentialRenewal original) {
        Objects.requireNonNull(independentPin, "independent account pin");
        byte[][] pin = independentPin.snapshot();
        byte[][] input = {ConfigurationInputs.copy(grant, 1, 65536, "credential grant"), pin[0], pin[1], pin[2], pin[3],
            Objects.requireNonNull(original, "original renewal").encoded()};
        return owner.call(false, handle -> new CredentialRenewalStatus(Native.credentialCommand(handle, 2, input, independentPin.version.bits)));
    }
    private CredentialRenewalStatus credentialPair(int command, Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        byte[][] input = {Objects.requireNonNull(original, "original renewal").encoded(), Objects.requireNonNull(statement, "original statement").encoded()};
        return owner.call(false, handle -> new CredentialRenewalStatus(Native.credentialCommand(handle, command, input, 0)));
    }
    public CredentialRenewalStatus reconcileExpiredCredentialRenewal(Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        return credentialPair(3, original, statement);
    }
    public CredentialRenewalProposal prepareWitnessedCredentialRenewal() {
        return owner.call(false, handle -> new CredentialRenewalProposal(Native.credentialCommand(handle, 4, new byte[0][], 0)));
    }
    public CredentialRenewalCancellation prepareWitnessedCredentialCancellation() {
        return owner.call(false, handle -> new CredentialRenewalCancellation(Native.credentialCommand(handle, 5, new byte[0][], 0)));
    }
    /** A new commit requires current authorization; terminal history releases no device. */
    public CredentialRenewalStatus commitWitnessedCredentialRenewal(Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        return credentialPair(6, original, statement);
    }
    /** Close can lose to Applied; that outcome remains Committed. */
    public CredentialRenewalStatus closeWitnessedCredentialRenewal(Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        return credentialPair(7, original, statement);
    }
    /** Sends neither Commit nor Close. Unavailable or failure never proves NoCommit. */
    public CredentialRenewalStatus reconcileWitnessedCredentialRenewal(Ids.CredentialRenewal original, Ids.CredentialStatement statement) {
        return credentialPair(8, original, statement);
    }
    /** Missing required witness enrollment is an error, never a local-mode fallback. */
    public ContinuityDevice activate() {
        return owner.transfer(handle -> {
            ContinuityDevice successor = new ContinuityDevice(handle);
            Native.action(handle, 4);
            return successor;
        });
    }
}
