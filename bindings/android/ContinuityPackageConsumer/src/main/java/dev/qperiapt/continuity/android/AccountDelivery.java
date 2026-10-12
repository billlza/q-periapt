// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** One selected recipient's result. Zero exchanges denotes a retained outcome;
 * unknown, pending, retired and abandoned outcomes do not assert consumption.
 */
public final class AccountDelivery {
    public enum Outcome { CONFIRMED, PREFIX_PENDING, RESOLUTION_PENDING, DELIVERY_UNKNOWN, HISTORY_RETIRED, RESERVATION_ABANDONED }
    private final byte[] device;
    private final Ids.Session session;
    private final Ids.Message message;
    private final Outcome outcome;
    private final int exchanges;
    AccountDelivery(byte[] wire, Ids.Session expectedSession) {
        if (wire == null || wire.length != 88) malformed();
        device = Arrays.copyOfRange(wire, 0, 16);
        byte[] sessionBytes = Arrays.copyOfRange(wire, 16, 48), messageBytes = Arrays.copyOfRange(wire, 48, 80);
        ByteBuffer counts = ByteBuffer.wrap(wire, 80, 8);
        int kind = counts.getInt(); exchanges = counts.getInt();
        if (!EnrollmentIntent.nonzero(device) || !EnrollmentIntent.nonzero(sessionBytes)
                || !EnrollmentIntent.nonzero(messageBytes) || kind < 1 || kind > 6 || exchanges < 0 || exchanges > 8
                || (kind == 2 && exchanges == 0)) malformed();
        session = new Ids.Session(sessionBytes);
        if (!session.equals(java.util.Objects.requireNonNull(expectedSession, "selected session"))) malformed();
        message = new Ids.Message(messageBytes); outcome = Outcome.values()[kind - 1];
    }
    private static void malformed() { throw new IllegalStateException("malformed native account delivery"); }
    public byte[] device() { return device.clone(); }
    public Ids.Session session() { return session; }
    public Ids.Message message() { return message; }
    public Outcome outcome() { return outcome; }
    public int exchanges() { return exchanges; }
}
