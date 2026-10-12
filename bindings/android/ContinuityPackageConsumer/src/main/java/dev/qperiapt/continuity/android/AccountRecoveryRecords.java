// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Complete original account metadata. Retired history does not prove consumption. */
public final class AccountRecoveryRecords {
    private AccountRecoveryRecords() { }
    public enum MemberState { COMMITTED, ACKNOWLEDGED, RESOLUTION_PENDING, DELIVERY_UNKNOWN, HISTORY_RETIRED, RESERVATION_ABANDONED }
    static AccountStatus status(byte[] bytes) {
        RecoveryWire w=new RecoveryWire(bytes,36);int phase=w.count(5);byte[] result=new byte[33];result[0]=(byte)phase;
        System.arraycopy(w.bytes(32),0,result,1,32);return new AccountStatus(result);
    }
    public static final class Header {
        private final Ids.AccountOperation operation;
        private final Ids.AccountAbandonment report;
        private final int count;
        Header(byte[] bytes) {
            RecoveryWire w=new RecoveryWire(bytes,72);operation=new Ids.AccountOperation(w.identity());report=new Ids.AccountAbandonment(w.identity());
            count=w.count(32);w.zero();if(count==0) RecoveryWire.malformed();
        }
        public Ids.AccountOperation operation() { return operation; }
        public Ids.AccountAbandonment report() { return report; }
        public int memberCount() { return count; }
    }
    public static final class Member {
        private final Counter64 generation,confirmed,sending,receiving,pending;
        private final ClosureRecords.Role role;
        private final int epochs;
        private final byte[] device,context;
        private final Ids.Session session;
        Member(byte[] bytes) {
            RecoveryWire w=new RecoveryWire(bytes,136);generation=w.counter();confirmed=w.counter();sending=w.counter();receiving=w.counter();
            Counter64 raw=w.counter();pending=RecoveryWire.optional(w.count(1),raw);role=ClosureRecords.role(w);epochs=w.count(4);w.zero();
            device=w.bytes(16);context=w.bytes(32);session=new Ids.Session(w.identity());RecoveryWire.nonzero(device);
            if(generation.bits==0 || epochs==0) RecoveryWire.malformed();
        }
        public Counter64 generation() { return generation; }
        public Counter64 confirmedEpoch() { return confirmed; }
        public Counter64 sendingEpoch() { return sending; }
        public Counter64 receivingEpoch() { return receiving; }
        public Counter64 pendingEpoch() { return pending; }
        public ClosureRecords.Role role() { return role; }
        public int epochCount() { return epochs; }
        public byte[] device() { return device.clone(); }
        public byte[] context() { return context.clone(); }
        public Ids.Session session() { return session; }
    }
    public static final class ReconciledMember {
        private final byte[] device;
        private final Ids.Session session;
        private final Ids.Message message;
        private final MemberState state;
        private ReconciledMember(byte[] bytes) {
            RecoveryWire w=new RecoveryWire(bytes,88);device=w.bytes(16);RecoveryWire.nonzero(device);
            session=new Ids.Session(w.identity());message=new Ids.Message(w.identity());int phase=w.count(6);w.zero();
            if(phase==0) RecoveryWire.malformed();state=MemberState.values()[phase-1];
        }
        public byte[] device() { return device.clone(); }
        public Ids.Session session() { return session; }
        public Ids.Message message() { return message; }
        public MemberState state() { return state; }
    }
    public static final class Reconciliation {
        private final Ids.AccountOperation operation;
        private final List<ReconciledMember> members;
        Reconciliation(byte[] bytes) {
            RecoveryWire w=new RecoveryWire(bytes,2856);operation=new Ids.AccountOperation(w.identity());int count=w.count(32);w.zero();
            if(count==0) RecoveryWire.malformed();List<ReconciledMember> parsed=new ArrayList<>(count);byte[] previous=null;
            for(int i=0;i<32;i++) {
                byte[] item=w.bytes(88);
                if(i>=count) {if(EnrollmentIntent.nonzero(item)) RecoveryWire.malformed();continue;}
                ReconciledMember member=new ReconciledMember(item);
                if(previous!=null && compare(previous,member.device)>=0) RecoveryWire.malformed();
                parsed.add(member);previous=member.device;
            }
            members=Collections.unmodifiableList(parsed);
        }
        private static int compare(byte[] a,byte[] b) {
            for(int i=0;i<16;i++) {int result=(a[i]&255)-(b[i]&255);if(result!=0) return result;}
            return 0;
        }
        public Ids.AccountOperation operation() { return operation; }
        public List<ReconciledMember> members() { return members; }
    }
}
