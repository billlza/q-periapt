// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Marshalling and calls on the original registry owner; native code owns all authorization. */
final class RootOperations {
    private RootOperations() { }
    static void empty(byte[] result) {
        if (result.length != 0) throw new IllegalStateException("native root result width");
    }
    static byte[] call(Owner owner, int operation, byte[][] fields) {
        return owner.call(false, handle -> Native.rootCommand(handle, 0, operation, fields, new long[0]));
    }
    static byte[] receipt(byte[] receipt, int minimum, int maximum) {
        return ConfigurationInputs.copy(receipt, minimum, maximum, "root receipt");
    }
    static void begin(Owner owner, ContinuityDevice device, RootReplacementScope scope, RootReplacementPlan plan) {
        byte[][] input = PolicyCodec.join(Objects.requireNonNull(scope, "root scope").snapshot(),
            new byte[][] {Objects.requireNonNull(plan, "independent root plan").encoded()});
        Objects.requireNonNull(device, "original device");
        owner.call(false, registry -> device.withOwner(handle -> {
            empty(Native.rootCommand(registry, handle, Native.ROOT_BEGIN, input, new long[0])); return null;
        }));
    }
    static void resume(Owner owner, int operation, String path, EnrollmentIntent intent,
            RootReplacementScope scope, byte[][] approval) {
        Objects.requireNonNull(intent, "original enrollment intent");
        byte[][] input = PolicyCodec.join(new byte[][] {Native.path(path)}, intent.snapshot(),
            Objects.requireNonNull(scope, "root scope").snapshot(), approval);
        long[] counters = {intent.generation.bits, intent.validFrom.bits, intent.validUntil.bits};
        owner.call(false, registry -> {
            empty(Native.rootCommand(registry, 0, operation, input, counters)); return null;
        });
    }
}
