// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.IntFunction;

/** Complete immutable loss reports. Construction never acknowledges host effects.
 * Bounds follow the candidate contract: 32 members, 4 epochs, 64 outstanding
 * records per direction, 128 skipped positions and one reservation per epoch.
 */
public final class CleanupReports {
    private CleanupReports() { }
    private static <T> List<T> collect(int count,int maximum,IntFunction<T> read) {
        if(count<0 || count>maximum) RecoveryWire.malformed();
        List<T> values=new ArrayList<>(count);
        for(int i=0;i<count;i++) values.add(read.apply(i));
        return Collections.unmodifiableList(values);
    }
    public static final class Epoch {
        private final ClosureRecords.Epoch metadata;
        private final List<ClosureRecords.Unconfirmed> unconfirmed;
        private final List<ClosureRecords.Delivery> deliveries;
        private final List<Counter64> skipped;
        private Epoch(ClosureRecords.Epoch metadata,IntFunction<ClosureRecords.Unconfirmed> unconfirmed,
                IntFunction<ClosureRecords.Delivery> deliveries,IntFunction<Counter64> skipped) {
            this.metadata=metadata;
            this.unconfirmed=collect(metadata.unconfirmedCount(),64,unconfirmed);
            this.deliveries=collect(metadata.deliveryCount(),64,deliveries);
            this.skipped=collect(metadata.skippedCount(),128,skipped);
        }
        public ClosureRecords.Epoch metadata() { return metadata; }
        public List<ClosureRecords.Unconfirmed> unconfirmed() { return unconfirmed; }
        public List<ClosureRecords.Delivery> deliveries() { return deliveries; }
        /** Positions alone do not prove peer messages existed. */
        public List<Counter64> skipped() { return skipped; }
    }
    public static final class Session {
        private final ClosureRecords.Header header;
        private final List<ClosureRecords.Reservation> reservations;
        private final List<Epoch> epochs;
        private Session(ContinuityRecovery owner) {
            header=owner.beginSessionCleanup();
            reservations=collect(header.reservationCount(),4,owner::sessionReservation);
            epochs=collect(header.epochCount(),4,i -> new Epoch(owner.sessionEpoch(i),
                j -> owner.sessionUnconfirmed(i,j),j -> owner.sessionDelivery(i,j),j -> owner.sessionSkipped(i,j)));
        }
        public ClosureRecords.Header header() { return header; }
        public List<ClosureRecords.Reservation> reservations() { return reservations; }
        public List<Epoch> epochs() { return epochs; }
    }
    public static final class Member {
        private final AccountRecoveryRecords.Member metadata;
        private final ClosureRecords.Reservation reservation;
        private final List<Epoch> epochs;
        private Member(ContinuityRecovery owner,int member) {
            metadata=owner.accountMember(member);reservation=owner.accountReservation(member);
            epochs=collect(metadata.epochCount(),4,i -> new Epoch(owner.accountEpoch(member,i),
                j -> owner.accountUnconfirmed(member,i,j),j -> owner.accountDelivery(member,i,j),j -> owner.accountSkipped(member,i,j)));
        }
        public AccountRecoveryRecords.Member metadata() { return metadata; }
        public ClosureRecords.Reservation reservation() { return reservation; }
        public List<Epoch> epochs() { return epochs; }
    }
    public static final class Account {
        private final AccountRecoveryRecords.Header header;
        private final List<Member> members;
        private Account(ContinuityRecovery owner) {
            header=owner.beginAccountCleanup();members=collect(header.memberCount(),32,i -> new Member(owner,i));
        }
        public AccountRecoveryRecords.Header header() { return header; }
        /** Every original member, in the native canonical order. */
        public List<Member> members() { return members; }
    }
    static Session session(ContinuityRecovery owner) { return new Session(owner); }
    static Account account(ContinuityRecovery owner) { return new Account(owner); }
}
