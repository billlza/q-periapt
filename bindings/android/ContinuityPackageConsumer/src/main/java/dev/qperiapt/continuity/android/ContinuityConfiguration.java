// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Arrays;
import java.util.Objects;

/** Owned first-use/configuration context over the original native persistent engine.
 * Preparation copies inputs without installation I/O. Run finishOpen off the Android UI thread.
 * An open failure never selects creation. After unknown creation, close and reconcile
 * the same original inputs. This owner grants no session or traffic authority.
 * Use try-with-resources or explicit close; GC does not dispose this Android API.
 */
public final class ContinuityConfiguration implements AutoCloseable {
    private final Owner owner;
    private ContinuityConfiguration(long handle) { owner = new Owner(handle); }
    private static ContinuityConfiguration own(long handle) {
        try { return new ContinuityConfiguration(handle); }
        catch (Throwable failure) {
            if (handle != 0) try { Native.action(handle, 3); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    private static ContinuityConfiguration prepare(String path, ConfigurationInputs.Initial input, int operation) {
        Objects.requireNonNull(input, "initial configuration");
        byte[][] snapshot = input.snapshot(Native.path(path));
        try { return own(Native.prepareConfiguration(snapshot, operation, input.trust.mode, input.protocol.version)); }
        finally { Arrays.fill(snapshot[12], (byte) 0); }
    }
    public static ContinuityConfiguration prepareCreate(String path, ConfigurationInputs.Initial input) {
        return prepare(path, input, 1);
    }
    public static ContinuityConfiguration prepareReconcile(String path, ConfigurationInputs.Initial original) {
        return prepare(path, original, 2);
    }
    public static ContinuityConfiguration prepareOpen(String path, ConfigurationInputs.SdkTrust trust,
            ConfigurationInputs.ProtocolPolicy protocol) {
        Objects.requireNonNull(trust, "SDK trust"); Objects.requireNonNull(protocol, "protocol policy");
        byte[][] sdk = trust.snapshot(), proto = protocol.snapshot();
        byte[][] inputs = {Native.path(path), sdk[0], sdk[1], sdk[2], new byte[0], new byte[0], new byte[0],
            proto[0], proto[1], proto[2], proto[3], new byte[0], new byte[0]};
        return own(Native.prepareConfiguration(inputs, 3, trust.mode, protocol.version));
    }
    public void finishOpen() { owner.action(1); }
    /** Move this finished configuration's independently trusted target policy into the
     * original enrollment. Selection alone approves or commits nothing. After success,
     * close this configuration; its moved policy lease remains with the enrollment.
     * An admitted error can consume both native owners: close and reopen the original
     * inputs. Cancellation, Busy and preflight failures retain their normal contracts.
     */
    public void selectContinuedPolicy(ContinuityEnrollment enrollment) {
        Objects.requireNonNull(enrollment, "original enrollment").selectPolicyFrom(owner);
    }
    /** Concurrent, one-way cancellation. Join the working thread, close, then resume original state. */
    public void cancel() { owner.action(2); }
    /** Busy preserves ownership. Other native errors retain their original code and diagnostic. */
    @Override public void close() { owner.close(); }
    private ContinuityEnrollment enrollment(EnrollmentIntent intent, ConfigurationWitness witness, int mode) {
        Objects.requireNonNull(intent, "enrollment intent");
        byte[][] scope = intent.snapshot();
        byte[][] pin = witness == null ? new byte[][] {new byte[0], new byte[0], new byte[0], new byte[0],
            new byte[0], new byte[0], new byte[0]} : witness.snapshot();
        try {
            byte[][] inputs = {scope[0], scope[1], scope[2], pin[0], pin[1], pin[2], pin[3], pin[4], pin[5], pin[6]};
            long[] counters = {intent.generation.bits, intent.validFrom.bits, intent.validUntil.bits};
            return owner.transfer(handle -> {
                ContinuityEnrollment successor = new ContinuityEnrollment(handle);
                Native.beginEnrollment(handle, inputs, counters, mode, witness == null ? 0 : witness.carrier, witness == null ? 0 : witness.timeout);
                return successor;
            });
        } finally { Arrays.fill(pin[5], (byte) 0); }
    }
    /** Null witness permits original inspection, never bypasses signed witness requirements. */
    public ContinuityEnrollment createEnrollment(EnrollmentIntent intent, ConfigurationWitness witness) { return enrollment(intent, witness, 1); }
    public ContinuityEnrollment resumeEnrollment(EnrollmentIntent original, ConfigurationWitness witness) { return enrollment(original, witness, 2); }
}
