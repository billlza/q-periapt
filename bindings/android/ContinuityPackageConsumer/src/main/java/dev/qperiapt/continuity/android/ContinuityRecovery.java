// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.util.Objects;

/** Cleanup-only original installation owner. No sending, key export or conversion
 * to an operational device is available. Unknown outcomes require the original
 * path/operation and current native status; they never imply absence.
 */
public final class ContinuityRecovery implements AutoCloseable {
    private final Owner owner;
    private ContinuityRecovery(long handle) { owner=new Owner(handle); }
    private static ContinuityRecovery own(long handle) {
        try { return new ContinuityRecovery(handle); }
        catch(Throwable failure) {
            if(handle!=0) try { Native.action(handle,3); } catch(Throwable cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    /** Copies bounded inputs only. finishOpen opens existing state, never provisions. */
    public static ContinuityRecovery prepare(String originalPath,RecoveryWitness witness) {
        Objects.requireNonNull(witness,"explicit original witness carrier");
        return own(Native.prepareRecovery(new byte[][] {Native.path(originalPath),witness.address()},witness.carrier,witness.timeout));
    }
    public void finishOpen() { owner.action(1); }
    public void cancel() { owner.action(2); }
    @Override public void close() { owner.close(); }
    private byte[] call(int operation,byte[] input,int member,int epoch,int index) {
        if(member<0 || epoch<0 || index<0) throw new IllegalArgumentException("negative recovery index");
        byte[][] fields=input==null ? new byte[0][] : new byte[][] {input};
        return owner.call(false,handle -> Native.recoveryCommand(handle,operation,fields,member,epoch,index));
    }
    private byte[] read(int operation) { return call(operation,null,0,0,0); }
    private void change(int operation,byte[] input) { if(call(operation,input,0,0,0).length!=0) RecoveryWire.malformed(); }
    private static byte[] id(Ids.Value value) { return Objects.requireNonNull(value,"original identity").encoded(); }
    /** Discovery is a hint; selection authenticates the original state. */
    public int sessionCount() { return new RecoveryWire(read(20),4).count(Integer.MAX_VALUE); }
    public Ids.Session sessionAt(int index) { return new Ids.Session(call(21,null,0,0,index)); }
    /** Selection consumes discovery; failed native selection requires close/reopen. */
    public void selectSession(Ids.Session session) { change(22,id(session)); }
    public void selectArchive(byte[] originalArchive) { change(23,ConfigurationInputs.copy(originalArchive,362,362,"closure archive")); }
    public byte[] archive() { byte[] result=read(24);if(result.length!=362) RecoveryWire.malformed();return result; }
    /** Permanently freezes this session. Read every counted entry before host accounting. */
    public ClosureRecords.Header beginSessionCleanup() { return new ClosureRecords.Header(read(25)); }
    /** Permanently freezes the session and reads EVERY report entry. A read error
     * throws without returning a partial report; freezing may already have committed.
     * Retain the original identity and retry. Persist the entire returned value and
     * its report ID in your host transaction before acknowledgeSession.
     * Cached report reads remain available after cancellation.
     */
    public CleanupReports.Session beginSessionCleanupReport() { return CleanupReports.session(this); }
    public ClosureRecords.Status sessionStatus() { return new ClosureRecords.Status(read(26)); }
    public ClosureRecords.Reservation sessionReservation(int index) { return new ClosureRecords.Reservation(call(27,null,0,0,index)); }
    public ClosureRecords.Epoch sessionEpoch(int epoch) { return new ClosureRecords.Epoch(call(28,null,0,epoch,0)); }
    public ClosureRecords.Unconfirmed sessionUnconfirmed(int epoch,int index) { return new ClosureRecords.Unconfirmed(call(29,null,0,epoch,index)); }
    public ClosureRecords.Delivery sessionDelivery(int epoch,int index) { return new ClosureRecords.Delivery(call(30,null,0,epoch,index)); }
    /** A skipped position does not prove a peer sent that message. */
    public Counter64 sessionSkipped(int epoch,int index) { return new RecoveryWire(call(31,null,0,epoch,index),8).counter(); }
    /** Only after all fields/report IDs are durable in a deduplicated host transaction. */
    public void acknowledgeSession(Ids.ClosureReport report) { change(32,id(report)); }
    /** Removes catalogue metadata only. Retain archive() first. */
    public boolean retireSession(Ids.ClosureReport report) {
        byte[] result=call(33,id(report),0,0,0);
        if(result.length!=1 || result[0]<0 || result[0]>1) RecoveryWire.malformed();return result[0]==1;
    }
    /** Restores authenticated catalogue metadata, never keys or send permission. */
    public void restoreSessionIndex() { change(34,null); }
    /** Authenticates ALL original members; no replacement recipient list is accepted. */
    public void selectAccount(Ids.AccountOperation original) { change(1,id(original)); }
    /** Freezes a reserved batch and retains one immutable complete report. */
    public AccountRecoveryRecords.Header beginAccountCleanup() { return new AccountRecoveryRecords.Header(read(2)); }
    /** Freezes the complete reserved batch and reads EVERY original member and
     * nested entry. Failure returns no partial report and never acknowledges it;
     * it may follow a committed freeze. Persist all fields and the report/operation
     * IDs durably before acknowledgeAccount. A committed batch cannot be relabeled
     * as reserved abandonment.
     * Cached report reads remain available after cancellation.
     */
    public CleanupReports.Account beginAccountCleanupReport() { return CleanupReports.account(this); }
    public AccountStatus accountStatus() { return AccountRecoveryRecords.status(read(3)); }
    /** Fresh native observation of all original members, including unknown outcomes. */
    public AccountRecoveryRecords.Reconciliation reconcileAccount() { return new AccountRecoveryRecords.Reconciliation(read(4)); }
    public AccountRecoveryRecords.Member accountMember(int member) { return new AccountRecoveryRecords.Member(call(5,null,member,0,0)); }
    /** Each member has exactly one reserved input. */
    public ClosureRecords.Reservation accountReservation(int member) { return new ClosureRecords.Reservation(call(6,null,member,0,0)); }
    public ClosureRecords.Epoch accountEpoch(int member,int epoch) { return new ClosureRecords.Epoch(call(7,null,member,epoch,0)); }
    public ClosureRecords.Unconfirmed accountUnconfirmed(int member,int epoch,int index) { return new ClosureRecords.Unconfirmed(call(8,null,member,epoch,index)); }
    public ClosureRecords.Delivery accountDelivery(int member,int epoch,int index) { return new ClosureRecords.Delivery(call(9,null,member,epoch,index)); }
    public Counter64 accountSkipped(int member,int epoch,int index) { return new RecoveryWire(call(10,null,member,epoch,index),8).counter(); }
    /** Requires every member/reservation/epoch/nested entry durably accounted for first. */
    public void acknowledgeAccount(Ids.AccountAbandonment report) { change(11,id(report)); }
    /** Requires acknowledged abandonment or settlement of EVERY committed member.
     * Keeps original session/bootstrap records and counters. Retain needed results first.
     */
    public void retireAccount() { change(12,null); }
}
