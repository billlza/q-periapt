// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** Complete private host metadata. Loading it performs no durable host accounting.
 * Persist all canonical bytes and the original proposal, then deduplicate accounting
 * by report identity before preparing an acknowledgement.
 */
public final class RetiredDeviceReport {
    private final Ids.RetiredReport report;
    private final int views;
    private final byte[] canonical;
    RetiredDeviceReport(byte[] wire) {
        if (wire.length < 48 + 323 || wire.length > 48 + 8388608)
            throw new IllegalStateException("native retirement report frame");
        ByteBuffer input = ByteBuffer.wrap(wire);
        long length = input.getLong(); views = input.getInt(); int reserved = input.getInt();
        byte[] id = new byte[32]; input.get(id);
        if (length != wire.length - 48 || views < 1 || views > 2 || reserved != 0 || !EnrollmentIntent.nonzero(id))
            throw new IllegalStateException("native retirement report metadata");
        canonical = Arrays.copyOfRange(wire, 48, wire.length);
        if (!RetiredReportProposal.magic(canonical, "QPRDMD01") && !RetiredReportProposal.magic(canonical, "QPRDMD02"))
            throw new IllegalStateException("native retirement report encoding");
        report = new Ids.RetiredReport(id);
    }
    public Ids.RetiredReport report() { return report; }
    public int viewCount() { return views; }
    public byte[] canonicalBytes() { return canonical.clone(); }
}
