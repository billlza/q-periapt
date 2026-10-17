// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Activated device owner; closing it revokes retained peer children. */
public final class ContinuityDevice implements AutoCloseable {
    private final Owner owner;
    ContinuityDevice(long handle) { owner = new Owner(handle); }
    <T> T withOwner(Owner.Call<T> call) { return owner.call(false, call); }
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
    /** Admit the independently pinned roster for a known remote account. Exact retry
     * still requires current local authority. Existing session operations check the
     * installed membership: retaining a member preserves its session; removal denies
     * further operations, including through existing children. After unknown results,
     * reopen the original device and reconcile the same target.
     */
    public RosterCheckpoint admitPeerRoster(byte[] roster, AccountPin independentPin) {
        byte[][] input = PolicyCodec.join(new byte[][] {ConfigurationInputs.copy(roster, 1, 65536, "peer roster")},
            PolicyCodec.pin(independentPin));
        return owner.call(false, handle -> RosterCheckpoint.decode(Native.rosterCommand(handle, Native.ROSTER_ADMIT_PEER, input)));
    }
    /** Read and retain before submitting; this does not reserve or dispatch work. */
    public Ids.AccountOperation nextAccountOperation() {
        return owner.call(false, handle -> new Ids.AccountOperation(
            Native.accountCommand(handle, 1, new long[0], new byte[0][], 0)));
    }
    public AccountStatus accountStatus(Ids.AccountOperation original) {
        byte[][] input = {java.util.Objects.requireNonNull(original, "original operation").encoded()};
        return owner.call(false, handle -> new AccountStatus(Native.accountCommand(handle, 2, new long[0], input, 0)));
    }
    private interface TargetCall<T> { T run(); }
    private static <T> T borrowTargets(AccountTarget[] targets, long[] handles, int index, TargetCall<T> operation) {
        if (index == targets.length) return operation.run();
        return targets[index].peer().withOwner(handle -> {
            handles[index] = handle;
            return borrowTargets(targets, handles, index + 1, operation);
        });
    }
    /** Admit the COMPLETE original target set and input, then deliver one member.
     * This is one native journal transaction, not a loop of individual sends.
     * Retain the same operation, account, targets and payload across retries and
     * members. Failure/cancellation may follow commitment. Remote effects are not
     * atomic, and local COMMITTED does not assert consumption by every recipient.
     * All target owners remain borrowed until return; native admission governs
     * concurrent close/cancel and requires live children of this exact device.
     */
    public AccountDelivery sendAccountMember(Ids.AccountOperation original, Ids.Account account,
            AccountTarget[] targets, int selected, String endpoint, byte[] plaintext, byte[] associatedData) {
        java.util.Objects.requireNonNull(targets, "complete target set");
        if (targets.length < 1 || targets.length > 32 || selected < 0 || selected >= targets.length)
            throw new IllegalArgumentException("account target count or selection");
        AccountTarget[] retained = targets.clone();
        byte[] sessions = new byte[retained.length * 32];
        for (int i = 0; i < retained.length; ++i) {
            java.util.Objects.requireNonNull(retained[i], "account target");
            System.arraycopy(retained[i].session().encoded(), 0, sessions, i * 32, 32);
        }
        byte[] operation = java.util.Objects.requireNonNull(original, "original operation").encoded();
        byte[] accountId = java.util.Objects.requireNonNull(account, "account").encoded();
        byte[] address = Native.path(endpoint);
        if (address.length > 128) throw new IllegalArgumentException("socket address width");
        java.util.Objects.requireNonNull(plaintext, "plaintext"); java.util.Objects.requireNonNull(associatedData, "associated data");
        if (plaintext.length > 16384 || associatedData.length > 1024) throw new IllegalArgumentException("message bound");
        byte[] payload = plaintext.clone();
        try {
            byte[] ad = associatedData.clone();
            try {
                long[] handles = new long[retained.length];
                byte[][] input = {operation, accountId, address, payload, ad, sessions};
                return owner.call(false, parent -> borrowTargets(retained, handles, 0, () ->
                    new AccountDelivery(Native.accountCommand(parent, 3, handles, input, selected), retained[selected].session())));
            } finally { java.util.Arrays.fill(ad, (byte)0); }
        } finally { java.util.Arrays.fill(payload, (byte)0); }
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
