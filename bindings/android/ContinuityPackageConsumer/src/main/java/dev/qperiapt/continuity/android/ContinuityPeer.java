// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/** One original peer/session owner, revoked when its device parent is closed.
 * Calls are synchronous. A nonzero result can follow commitment; query and retry
 * the SAME original operation/input, never substitute a newly generated ID.
 */
public final class ContinuityPeer implements AutoCloseable {
    public enum MessageStatus { ABSENT, RESERVED, COMMITTED, ACKNOWLEDGED, RESOLUTION_PENDING, DELIVERY_UNKNOWN, RESERVATION_ABANDONED }
    public enum Consumption { CONFIRMED, PREFIX_PENDING }
    public static final class Establishment {
        private final Ids.Session session;
        private final int exchanges;
        private Establishment(byte[] wire) {
            if (wire.length != 34) malformed();
            session = new Ids.Session(Arrays.copyOf(wire, 32)); exchanges = ContinuityPeer.exchanges(wire, 32);
        }
        public Ids.Session session() { return session; }
        public int exchanges() { return exchanges; }
    }
    public static final class SendResult {
        private final Consumption consumption;
        private final int exchanges;
        private SendResult(byte[] wire) {
            if (wire.length != 3 || wire[0] < 1 || wire[0] > 2) malformed();
            consumption = Consumption.values()[wire[0] - 1]; exchanges = ContinuityPeer.exchanges(wire, 1);
        }
        public Consumption consumption() { return consumption; }
        public int exchanges() { return exchanges; }
    }
    private final Owner owner;
    private ContinuityPeer(long handle) { owner = new Owner(handle); }
    static ContinuityPeer own(long handle) {
        try { return new ContinuityPeer(handle); }
        catch (Throwable failure) {
            if (handle != 0) try { Native.action(handle, 3); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    private static void malformed() { throw new IllegalStateException("malformed native transport result"); }
    private static int exchanges(byte[] wire, int offset) {
        int count = (wire[offset] & 255) * 256 + (wire[offset + 1] & 255);
        if (count < 1 || count > 8) malformed();
        return count;
    }
    private static byte[] endpoint(String peer) {
        byte[] bytes = Native.path(peer);
        if (bytes.length > 128) throw new IllegalArgumentException("socket address width");
        return bytes;
    }
    public void finishOpen() { owner.action(1); }
    public void cancel() { owner.action(2); }
    @Override public void close() { owner.close(); }
    public Establishment establish(String endpoint, Ids.Initiation original) {
        byte[][] input = {endpoint(endpoint), Objects.requireNonNull(original, "initiation").encoded()};
        return owner.call(false, handle -> new Establishment(Native.peerCommand(handle, 1, input, 0)));
    }
    /** Queries the next slot without reserving it; competing calls may observe the same ID. */
    public Ids.Message nextMessage(Ids.Session session) {
        byte[][] input = {Objects.requireNonNull(session, "session").encoded()};
        return owner.call(false, handle -> new Ids.Message(Native.peerCommand(handle, 2, input, 0)));
    }
    public MessageStatus messageStatus(Ids.Session session, Ids.Message message) {
        byte[][] input = {Objects.requireNonNull(session, "session").encoded(), Objects.requireNonNull(message, "message").encoded()};
        return owner.call(false, handle -> {
            byte[] wire = Native.peerCommand(handle, 3, input, 0);
            if (wire.length != 1 || wire[0] < 0 || wire[0] > 6) malformed();
            return MessageStatus.values()[wire[0]];
        });
    }
    public SendResult send(String endpoint, Ids.Session session, Ids.Message original, byte[] plaintext, byte[] associatedData) {
        byte[] address = endpoint(endpoint), sessionId = Objects.requireNonNull(session, "session").encoded();
        byte[] message = Objects.requireNonNull(original, "message").encoded();
        Objects.requireNonNull(plaintext, "plaintext"); Objects.requireNonNull(associatedData, "associated data");
        if (plaintext.length > 16384 || associatedData.length > 1024) throw new IllegalArgumentException("message bound");
        byte[] payload = plaintext.clone();
        try {
            byte[] ad = associatedData.clone();
            try {
                byte[][] input = {address, sessionId, message, payload, ad};
                return owner.call(false, handle -> new SendResult(Native.peerCommand(handle, 4, input, 0)));
            } finally { Arrays.fill(ad, (byte) 0); }
        } finally { Arrays.fill(payload, (byte) 0); }
    }
    public Counter64 rekey(String endpoint, Ids.Session session, Counter64 target) {
        Objects.requireNonNull(target, "target epoch");
        byte[][] input = {endpoint(endpoint), Objects.requireNonNull(session, "session").encoded()};
        return owner.call(false, handle -> {
            byte[] wire = Native.peerCommand(handle, 5, input, target.bits);
            if (wire.length != 8) malformed();
            Counter64 completed = Counter64.fromBits(ByteBuffer.wrap(wire).getLong());
            if (!completed.equals(target)) malformed();
            return completed;
        });
    }
    /** Bind one listener; port zero requests an ephemeral port. */
    public int listen(String address) {
        byte[][] input = {endpoint(address)};
        return owner.call(false, handle -> {
            byte[] wire = Native.peerServer(handle, 1, input, null);
            if (wire.length != 2) malformed();
            int port = (wire[0] & 255) * 256 + (wire[1] & 255);
            if (port == 0) malformed();
            return port;
        });
    }
    public Served serve(ApplicationCommit commit) {
        Native.CommitInvocation invocation = new Native.CommitInvocation(commit);
        try {
            Served result = owner.call(false, handle -> new Served(Native.peerServer(handle, 2, new byte[0][], invocation)));
            int expected = result.kind() == Served.Kind.MESSAGE && !result.duplicate() ? 1 : 0;
            if (invocation.failure != null || invocation.count != expected) {
                throw new IllegalStateException("native callback outcome differs from consumption", invocation.failure);
            }
            return result;
        } catch (ContinuityFailure failure) {
            if (invocation.failure != null) failure.initCause(invocation.failure);
            throw failure;
        }
    }
    public Counter64 serveRekey(Ids.Session session) {
        byte[][] input = {Objects.requireNonNull(session, "session").encoded()};
        return owner.call(false, handle -> {
            byte[] wire = Native.peerServer(handle, 3, input, null);
            if (wire.length != 8) malformed();
            return Counter64.fromBits(ByteBuffer.wrap(wire).getLong());
        });
    }
}
