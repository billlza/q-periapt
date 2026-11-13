// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** Immutable loss metadata; no record grants permission or proves unknown delivery. */
public final class ClosureRecords {
    private ClosureRecords() { }
    public enum Role { INITIATOR, RESPONDER }
    public enum Phase { OPEN, PENDING, CLOSED }
    public enum Resolution { UNREQUESTED, PENDING, ACKNOWLEDGED }
    static Role role(RecoveryWire wire) {
        int value=wire.count(2);if(value==0) RecoveryWire.malformed();return Role.values()[value-1];
    }
    public static final class Status {
        private final Phase phase;
        private final Ids.ClosureReport report;
        Status(byte[] bytes) {
            RecoveryWire wire=new RecoveryWire(bytes,36);phase=Phase.values()[wire.count(2)];byte[] id=wire.bytes(32);
            if((phase==Phase.OPEN)==EnrollmentIntent.nonzero(id)) RecoveryWire.malformed();
            report=phase==Phase.OPEN ? null : new Ids.ClosureReport(id);
        }
        public Phase phase() { return phase; }
        /** Present only for PENDING/CLOSED. */
        public Ids.ClosureReport report() { return report; }
    }
    public static final class Header {
        private final Counter64 generation,confirmed,sending,receiving,pending;
        private final Role role;
        private final int reservations,epochs;
        private final Ids.Session session;
        private final Ids.ClosureReport report;
        private final Ids.Account account;
        private final byte[] context,device;
        Header(byte[] bytes) {
            RecoveryWire w=new RecoveryWire(bytes,200);generation=w.counter();confirmed=w.counter();sending=w.counter();receiving=w.counter();
            Counter64 raw=w.counter();pending=RecoveryWire.optional(w.count(1),raw);role=ClosureRecords.role(w);
            reservations=w.count(Integer.MAX_VALUE);epochs=w.count(4);
            session=new Ids.Session(w.identity());context=w.bytes(32);report=new Ids.ClosureReport(w.identity());
            account=new Ids.Account(w.identity());device=w.bytes(16);RecoveryWire.nonzero(device);
            if(generation.bits==0) RecoveryWire.malformed();
        }
        public Counter64 generation() { return generation; }
        public Counter64 confirmedEpoch() { return confirmed; }
        public Counter64 sendingEpoch() { return sending; }
        public Counter64 receivingEpoch() { return receiving; }
        public Counter64 pendingEpoch() { return pending; }
        public Role role() { return role; }
        public int reservationCount() { return reservations; }
        public int epochCount() { return epochs; }
        public Ids.Session session() { return session; }
        public Ids.ClosureReport report() { return report; }
        public Ids.Account peerAccount() { return account; }
        public byte[] context() { return context.clone(); }
        public byte[] peerDevice() { return device.clone(); }
    }
    public static final class Reservation {
        private final Counter64 plaintext,ad;
        private final Ids.Message message;
        Reservation(byte[] bytes) {
            RecoveryWire w=new RecoveryWire(bytes,48);plaintext=w.counter();ad=w.counter();message=new Ids.Message(w.identity());
        }
        public Counter64 plaintextBytes() { return plaintext; }
        public Counter64 associatedDataBytes() { return ad; }
        public Ids.Message message() { return message; }
    }
    public static final class Epoch {
        private final Counter64 epoch,acknowledged,sent,consumed,received,peerSent;
        private final Resolution resolution;
        private final Ids.ResolutionReport report;
        private final int unconfirmed,deliveries,skipped;
        Epoch(byte[] bytes) {
            RecoveryWire w=new RecoveryWire(bytes,104);epoch=w.counter();acknowledged=w.counter();sent=w.counter();consumed=w.counter();received=w.counter();
            Counter64 raw=w.counter();peerSent=RecoveryWire.optional(w.count(1),raw);resolution=Resolution.values()[w.count(2)];
            unconfirmed=w.count(Integer.MAX_VALUE);deliveries=w.count(Integer.MAX_VALUE);skipped=w.count(Integer.MAX_VALUE);w.zero();
            byte[] id=w.bytes(32);
            if((resolution==Resolution.UNREQUESTED)==EnrollmentIntent.nonzero(id)) RecoveryWire.malformed();
            report=resolution==Resolution.UNREQUESTED ? null : new Ids.ResolutionReport(id);
        }
        public Counter64 epoch() { return epoch; }
        public Counter64 acknowledgedBefore() { return acknowledged; }
        public Counter64 sent() { return sent; }
        public Counter64 consumedBefore() { return consumed; }
        public Counter64 received() { return received; }
        public Counter64 peerSent() { return peerSent; }
        public Resolution resolution() { return resolution; }
        public Ids.ResolutionReport resolutionReport() { return report; }
        public int unconfirmedCount() { return unconfirmed; }
        public int deliveryCount() { return deliveries; }
        public int skippedCount() { return skipped; }
    }
    public static final class Unconfirmed {
        private final Ids.Message message;
        private final byte[] digest;
        Unconfirmed(byte[] bytes) { RecoveryWire w=new RecoveryWire(bytes,64);message=new Ids.Message(w.identity());digest=w.bytes(32); }
        public Ids.Message message() { return message; }
        /** Native ciphertext commitment, never a plaintext hash. */
        public byte[] ciphertextDigest() { return digest.clone(); }
    }
    public static final class Delivery {
        private final Counter64 index,plaintext;
        private final Ids.Message message;
        Delivery(byte[] bytes) { RecoveryWire w=new RecoveryWire(bytes,48);index=w.counter();plaintext=w.counter();message=new Ids.Message(w.identity()); }
        public Counter64 index() { return index; }
        public Counter64 plaintextBytes() { return plaintext; }
        public Ids.Message message() { return message; }
    }
}
