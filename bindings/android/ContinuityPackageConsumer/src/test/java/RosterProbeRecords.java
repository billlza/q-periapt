// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;
import dev.qperiapt.continuity.android.*;
import java.nio.ByteBuffer;

/** Test-only explicit encoding of public roster progress; not a new protocol format. */
final class RosterProbeRecords {
    private RosterProbeRecords() { }
    private static long bits(Counter64 value) { return Long.parseUnsignedLong(value.toString()); }
    private static void checkpoint(ByteBuffer b,RosterCheckpoint c) { b.putLong(bits(c.version())).put(c.digest()); }
    static byte[] progress(RosterRefreshProgress value) {
        ByteBuffer b=ByteBuffer.allocate(624);b.putInt(value.phase().ordinal()).putInt(value.retired()?1:0);
        RosterRefreshScope scope=value.scope();
        if(scope!=null) {
            b.put(scope.operation().encoded());checkpoint(b,scope.previous());checkpoint(b,scope.target());
            b.putLong(bits(scope.policy().version())).put(scope.policy().digest());
            Ids.PolicyAuthorization authorization=scope.policyAuthorization();
            b.put(authorization==null?new byte[32]:authorization.encoded()).putInt(authorization==null?0:1).putInt(0);
            if(value.proposal()!=null)b.put(value.proposal().encoded());
        }
        return b.array();
    }
}
