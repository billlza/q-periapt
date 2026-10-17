// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;

/** Private explicit big-endian JNI framing; never a signed protocol or native memory image. */
final class PolicyCodec {
    private PolicyCodec() { }
    static byte[] take(ByteBuffer input, int length) {
        byte[] value = new byte[length]; input.get(value); return value;
    }
    static byte[] identity(byte[] input, String name) {
        byte[] result = ConfigurationInputs.copy(input, 32, 32, name);
        if (!EnrollmentIntent.nonzero(result)) throw new IllegalArgumentException(name);
        return result;
    }
    static void checkpoint(ByteBuffer output, RosterCheckpoint value) {
        output.putLong(value.version().bits).put(value.digest());
    }
    static void checkpoint(ByteBuffer output, PolicyCheckpoint value) {
        output.putLong(value.version().bits).put(value.digest());
    }
    static RosterCheckpoint roster(ByteBuffer input) {
        return new RosterCheckpoint(Counter64.fromBits(input.getLong()), take(input, 32));
    }
    static PolicyCheckpoint policy(ByteBuffer input) {
        return new PolicyCheckpoint(Counter64.fromBits(input.getLong()), take(input, 32));
    }
    static byte[][] document(ConfigurationInputs.ProtocolPolicy value) {
        java.util.Objects.requireNonNull(value, "policy document");
        byte[][] fields = value.snapshot();
        return new byte[][] {fields[0], fields[1], ByteBuffer.allocate(8).putLong(value.version).array(), fields[2], fields[3]};
    }
    static byte[][] pin(AccountPin value) {
        java.util.Objects.requireNonNull(value, "account pin");
        byte[][] fields = value.snapshot();
        return new byte[][] {fields[0], fields[1], fields[2], ByteBuffer.allocate(8).putLong(value.version.bits).array(), fields[3]};
    }
    static byte[][] join(byte[][]... groups) {
        int count = 0; for (byte[][] group : groups) count += group.length;
        byte[][] result = new byte[count][]; int offset = 0;
        for (byte[][] group : groups) { System.arraycopy(group, 0, result, offset, group.length); offset += group.length; }
        return result;
    }
    static byte[] publicRecord(ByteBuffer input) {
        int length = input.getInt();
        if (length < 1 || length > 8192) throw new IllegalArgumentException("public record length");
        byte[] result = take(input, length);
        for (int i = length; i < 8192; ++i)
            if (input.get() != 0) throw new IllegalArgumentException("public record tail");
        return result;
    }
    static void publicRecord(ByteBuffer output, byte[] bytes) {
        output.putInt(bytes.length).put(bytes);
        output.position(output.position() + 8192 - bytes.length);
    }
}
