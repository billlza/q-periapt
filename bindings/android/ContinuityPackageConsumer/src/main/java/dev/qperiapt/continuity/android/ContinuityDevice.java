// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Activated device owner; closing it revokes retained peer children. */
public final class ContinuityDevice implements AutoCloseable {
    private final Owner owner;
    ContinuityDevice(long handle) { owner = new Owner(handle); }
    public void cancel() { owner.action(2); }
    @Override public void close() { owner.close(); }
    /** Admit an independently approved remote grant on this original device.
     * Reopen original peer/session owners after success; cached children are not
     * refreshed. This cannot renew the local identity or create a new session.
     * A failed/unknown result is not absence: close/reopen the original owners
     * and reconcile the SAME grant and operation, never replace the journal.
     */
    public RosterCheckpoint admitPeerCredentialRenewal(byte[] grant, AccountPin independentPin, Ids.CredentialRenewal original) {
        java.util.Objects.requireNonNull(independentPin, "independent account pin");
        byte[][] pin = independentPin.snapshot();
        byte[][] input = {ConfigurationInputs.copy(grant, 1, 65536, "peer credential grant"), pin[0], pin[1], pin[2], pin[3],
            java.util.Objects.requireNonNull(original, "original renewal").encoded()};
        return owner.call(false, handle -> RosterCheckpoint.decode(Native.credentialCommand(handle, 9, input, independentPin.version.bits)));
    }
    private ContinuityPeer prepare(PeerConfiguration configuration, PeerConfiguration.Quality quality,
            PeerConfiguration.Role role, Ids.Session session) {
        java.util.Objects.requireNonNull(configuration, "peer configuration");
        java.util.Objects.requireNonNull(quality, "prekey quality"); java.util.Objects.requireNonNull(role, "role");
        byte[][] inputs = configuration.snapshot(session); long[] counters = configuration.counters();
        return owner.call(false, handle -> ContinuityPeer.own(Native.preparePeer(handle, inputs, counters, quality.ordinal() + 1, role.ordinal() + 1, session != null)));
    }
    public ContinuityPeer preparePeer(PeerConfiguration configuration, PeerConfiguration.Quality quality, PeerConfiguration.Role role) {
        return prepare(configuration, quality, role, null);
    }
    public ContinuityPeer preparePeerReopen(PeerConfiguration configuration, PeerConfiguration.Quality quality,
            PeerConfiguration.Role role, Ids.Session original) {
        return prepare(configuration, quality, role, java.util.Objects.requireNonNull(original, "original session"));
    }
}
