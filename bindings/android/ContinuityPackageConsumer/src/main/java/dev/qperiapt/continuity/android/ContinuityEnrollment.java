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
    /** Missing required witness enrollment is an error, never a local-mode fallback. */
    public ContinuityDevice activate() {
        return owner.transfer(handle -> {
            ContinuityDevice successor = new ContinuityDevice(handle);
            Native.action(handle, 4);
            return successor;
        });
    }
}
