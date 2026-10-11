// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Independent persistent account registry. Keep its path, key and original trust
 * outside device-journal backups. Explicit close revokes managed child admission;
 * cancellation only stops this handle's calls. Reopen does not revive old children.
 */
public final class ContinuityAccountAuthority implements AutoCloseable {
    private final Owner owner;
    private ContinuityAccountAuthority(long handle) { owner = new Owner(handle); }
    private static ContinuityAccountAuthority own(long handle) {
        try { return new ContinuityAccountAuthority(handle); }
        catch (Throwable failure) {
            if (handle != 0) try { Native.action(handle, 3); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    /** Explicit first-use only, within an existing private directory. Never repairs a missing key. */
    public static void provisionWrappingKey(String directory) { Native.provisionAuthority(new byte[][] {Native.path(directory)}); }
    private static ContinuityAccountAuthority prepare(String directory, AccountAuthorityTrust trust, boolean create) {
        return own(Native.prepareAuthority(Objects.requireNonNull(trust, "registry trust").snapshot(Native.path(directory)), create));
    }
    public static ContinuityAccountAuthority prepareCreate(String directory, AccountAuthorityTrust trust) { return prepare(directory, trust, true); }
    public static ContinuityAccountAuthority prepareOpen(String directory, AccountAuthorityTrust trust) { return prepare(directory, trust, false); }
    public void finishOpen() { owner.action(1); }
    public void cancel() { owner.action(2); }
    @Override public void close() { owner.close(); }
    public AccountAuthorityCheckpoint checkpoint(Ids.ApplicationAccount application) {
        byte[][] input = {Objects.requireNonNull(application, "application account").encoded()};
        return owner.call(false, handle -> AccountAuthorityCheckpoint.fromWire(Native.authorityCommand(handle, 1, input, 0)));
    }
    /** Associate independently approved, signature-verified enrollment inputs.
     * An error may follow commit: retain original inputs and inspect the checkpoint.
     */
    public AccountAuthorityCheckpoint associate(Ids.ApplicationAccount application, AccountPin independentPin,
            byte[] certificate, byte[] roster) {
        Objects.requireNonNull(independentPin, "independent account pin");
        byte[][] pin = independentPin.snapshot();
        byte[][] input = {Objects.requireNonNull(application, "application account").encoded(), pin[0], pin[1], pin[2], pin[3],
            ConfigurationInputs.copy(certificate, 1, 8192, "certificate"), ConfigurationInputs.copy(roster, 1, 8192, "roster")};
        return owner.call(false, handle -> AccountAuthorityCheckpoint.fromWire(
            Native.authorityCommand(handle, 2, input, independentPin.version.bits)));
    }
    void select(Owner enrollment, AccountAuthorityCheckpoint checkpoint) {
        byte[][] input = {checkpoint.wire()};
        owner.call(false, registry -> enrollment.call(false, handle -> {
            Native.selectAuthority(handle, registry, input); return null;
        }));
    }
}
