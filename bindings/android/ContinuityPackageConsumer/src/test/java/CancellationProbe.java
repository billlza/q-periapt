// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.*;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

/** Actual accept calls, native Busy admission, cancellation and parent revocation. */
final class CancellationProbe {
    private CancellationProbe() { }
    private static void require(boolean condition, String reason) { if (!condition) throw new AssertionError(reason); }
    private static void fails(int code, Runnable call) {
        try { call.run(); }
        catch (ContinuityFailure failure) { require(failure.code() == code, "expected " + code + ", got " + failure); return; }
        throw new AssertionError("expected failure " + code);
    }
    private static ContinuityPeer open(ContinuityDevice parent, PeerConfiguration config, Ids.Session session) {
        ContinuityPeer peer = parent.preparePeerReopen(config, PeerConfiguration.Quality.ONE_TIME_BOTH, PeerConfiguration.Role.INITIATOR, session);
        try { peer.finishOpen(); return peer; }
        catch (Throwable failure) {
            try { peer.close(); } catch (Throwable cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    static void run(Path inputs, Path path, boolean recovery, Ids.Session session, PeerConfiguration config) throws Exception {
        for (boolean cancelParent : new boolean[] {false, true}) {
            try (ContinuityDevice device = PeerProbe.device(inputs, path, recovery);
                    ContinuityPeer peer = open(device, config, session);
                    ContinuityPeer observer = open(device, config, session)) {
                ContinuityPeer idle = open(device, config, session);
                boolean idleClosed = false;
                AtomicReference<Throwable> result = new AtomicReference<>();
                Thread receiver = new Thread(() -> {
                    try {
                        for (int admission = 0; ; admission++) {
                            try {
                                peer.serve((s, m, bytes) -> { throw new AssertionError("unexpected incoming message"); });
                                result.set(new AssertionError("empty listener succeeded"));
                                break;
                            } catch (ContinuityFailure failure) {
                                // The observing query can win admission. Retry only
                                // pre-I/O Busy; never a transport or commit failure.
                                if (failure.code() != 3 || admission == 64) throw failure;
                                Thread.sleep(1);
                            }
                        }
                    } catch (Throwable failure) { result.set(failure); }
                }, "continuity-receiver");
                receiver.setDaemon(true);
                try {
                    Ids.Message probe = peer.nextMessage(session);
                    peer.listen("127.0.0.1:0"); receiver.start();
                    long deadline = System.nanoTime() + 5_000_000_000L;
                    boolean busy = false;
                    while (System.nanoTime() < deadline && receiver.isAlive()) {
                        try { observer.messageStatus(session, probe); }
                        catch (ContinuityFailure failure) {
                            require(failure.code() == 3, "unexpected admission: " + failure);
                            busy = true; break;
                        }
                        Thread.sleep(2);
                    }
                    require(busy, "serve did not acquire native admission: " + result.get());
                    fails(3, peer::close); fails(3, device::close);
                    idle.close(); idleClosed = true; // An idle child closes without the active service lock.
                    AtomicReference<Throwable> cancellation = new AtomicReference<>();
                    Thread canceller = new Thread(() -> {
                        try { if (cancelParent) device.cancel(); else peer.cancel(); }
                        catch (Throwable failure) { cancellation.set(failure); }
                    }, "continuity-canceller");
                    canceller.setDaemon(true); canceller.start(); canceller.join(5000);
                    require(!canceller.isAlive() && cancellation.get() == null, "cancellation blocked or failed: " + cancellation.get());
                    receiver.join(5000);
                    require(!receiver.isAlive(), "cancel did not release accept");
                    require(result.get() instanceof ContinuityFailure && ((ContinuityFailure) result.get()).code() == 302,
                        "accept did not return cancellation: " + result.get());
                    fails(302, () -> peer.messageStatus(session, probe));
                    if (cancelParent) fails(302, () -> observer.messageStatus(session, probe));
                    else require(observer.messageStatus(session, probe) == ContinuityPeer.MessageStatus.ABSENT, "child cancel revoked sibling");
                } finally {
                    if (receiver.isAlive()) { peer.cancel(); receiver.join(25000); require(!receiver.isAlive(), "receiver cleanup deadline"); }
                    if (!idleClosed) idle.close();
                }
            }
        }
        ContinuityDevice device = PeerProbe.device(inputs, path, recovery);
        boolean closed = false;
        try (ContinuityPeer pending = device.preparePeerReopen(config, PeerConfiguration.Quality.ONE_TIME_BOTH, PeerConfiguration.Role.INITIATOR, session)) {
            device.close(); closed = true;
            fails(2, pending::finishOpen);
        } finally { if (!closed) device.close(); }
    }
}
