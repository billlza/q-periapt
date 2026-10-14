// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Internal JNI marshalling only. This process-lifetime bridge requires deterministic owner close. */
final class Native {
    static { System.loadLibrary("qperiapt_continuity_jni"); }
    static final int ROOT_BEGIN=1, ROOT_RESUME=2, ROOT_STATE=3, ROOT_BIND_FREEZE=4,
        ROOT_RETAIN_RETIREMENT=5, ROOT_RETAIN_NONCOMMIT=6, ROOT_ACTIVATE=7,
        ROOT_TRANSITION=8, ROOT_ADOPT=9, ROOT_RESUME_TRANSITION=10, ROOT_RESUME_ADOPTION=11;
    static native byte[] rootCommand(long registry, long other, int operation, byte[][] inputs, long[] counters);
    private Native() { }
    static byte[] path(String value) {
        if (value == null) throw new NullPointerException("path");
        if (value.isEmpty() || value.length() > 4096 || value.indexOf('\0') >= 0) throw new IllegalArgumentException("path");
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));
            if (encoded.remaining() > 4096) throw new IllegalArgumentException("UTF-8 path exceeds bound");
            byte[] bytes = new byte[encoded.remaining()]; encoded.get(bytes); return bytes;
        } catch (CharacterCodingException failure) { throw new IllegalArgumentException("path is not canonical UTF-8", failure); }
    }
    // Called by JNI after validating the complete error record. Never substitutes a success value.
    private static void fail(String operation, int code, byte[] diagnostic, boolean truncated) {
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(diagnostic)).toString();
            throw new ContinuityFailure(operation, code, text, truncated);
        } catch (CharacterCodingException failure) { throw new IllegalStateException("malformed native diagnostic", failure); }
    }
    static native long prepareConfiguration(byte[][] inputs, int operation, int trust, long version);
    static native void action(long handle, int operation);
    static native void beginEnrollment(long handle, byte[][] inputs, long[] counters, int mode, int carrier, int timeout);
    static native byte[] enrollmentQuery(long handle, int operation);
    static native byte[] enrollmentAccept(long handle, byte[][] inputs, long version);
    static native long preparePeer(long parent, byte[][] inputs, long[] counters, int quality, int role, boolean reopen);
    static native byte[] accountCommand(long parent, int operation, long[] peers, byte[][] inputs, int selected);
    static native long prepareRecovery(byte[][] inputs, int carrier, int timeout);
    static native byte[] recoveryCommand(long handle, int operation, byte[][] inputs, int member, int epoch, int index);
    static native byte[] peerCommand(long handle, int operation, byte[][] inputs, long target);
    static native byte[] peerServer(long handle, int operation, byte[][] inputs, Object callback);
    static native void provisionAuthority(byte[][] inputs);
    static native long prepareAuthority(byte[][] inputs, boolean create);
    static native byte[] authorityCommand(long handle, int operation, byte[][] inputs, long version);
    static native void selectAuthority(long enrollment, long registry, byte[][] checkpoint);
    static native byte[] credentialCommand(long handle, int operation, byte[][] inputs, long version);
    static final int CREDENTIAL_STAGE_CONTINUED = 10, CREDENTIAL_PREPARE_CONTINUED = 11,
        CREDENTIAL_CANCEL_CONTINUED = 12, CREDENTIAL_COMMIT_CONTINUED = 13,
        CREDENTIAL_RECONCILE_LOCAL = 14, CREDENTIAL_RECOVER_HISTORICAL = 15,
        CREDENTIAL_REQUEST = 16, CREDENTIAL_WITNESSED_REQUEST = 17,
        CREDENTIAL_STAGE_JOINT = 18, CREDENTIAL_ACTIVATE_JOINT = 19;
    // Private JNI selectors; independent policy operations never use credential grammar.
    static final int POLICY_REQUEST = 1, POLICY_WITNESSED_REQUEST = 2, POLICY_STATUS = 3,
        POLICY_RECONCILE = 4, POLICY_APPROVAL = 5, POLICY_PREPARE = 6, POLICY_PREPARATION = 7,
        POLICY_PROGRESS = 8, POLICY_COMMIT = 9, POLICY_WITNESS_RECONCILE = 10, POLICY_CLOSE = 11,
        POLICY_STAGE = 12, POLICY_RESOLVE = 13, POLICY_ACTIVATE = 14;
    static final int ROSTER_REFRESH = 1, ROSTER_RESOLVE = 2, ROSTER_PREPARE = 3, ROSTER_PREPARATION = 4,
        ROSTER_PROGRESS = 5, ROSTER_ABANDON = 6, ROSTER_COMMIT = 7, ROSTER_RECONCILE = 8, ROSTER_CLOSE = 9, ROSTER_ADMIT_PEER = 10, ROSTER_REFRESH_WITH_POLICY = 11;
    static native byte[] rosterCommand(long handle, int operation, byte[][] inputs);
    static native byte[] policyCommand(long handle, int operation, byte[][] inputs);
    static native void selectPolicy(long configuration, long enrollment);
    static native long prepareRetired(byte[][] inputs, long[] counters);
    static native byte[] retiredCommand(long handle, int operation, byte[][] inputs);
    static native byte[] pendingWriteCommand(long handle, int operation, byte[][] inputs);
    static final int RETIRED_INVENTORY = 1, RETIRED_PREPARE_REPORT = 2, RETIRED_REPORT_PROPOSAL = 3,
        RETIRED_LOAD_REPORT = 4, RETIRED_PREPARE_ACK = 5, RETIRED_ACK_PROPOSAL = 6,
        RETIRED_JOURNAL_STATE = 7, RETIRED_ERASE_JOURNAL = 8, RETIRED_PREPARE_SIGNER = 9,
        RETIRED_SIGNER_STATE = 10, RETIRED_ERASE_SIGNER = 11;
    static final class CommitInvocation {
        private final ApplicationCommit commit;
        Throwable failure;
        int count;
        CommitInvocation(ApplicationCommit commit) { this.commit = java.util.Objects.requireNonNull(commit, "application transaction"); }
        int invoke(byte[] session, byte[] message, byte[] plaintext) {
            try {
                count += 1;
                if (count != 1) throw new IllegalStateException("native callback invoked more than once");
                commit.commit(new Ids.Session(session), new Ids.Message(message), plaintext);
                return 0;
            } catch (Throwable error) {
                failure = error;
                return 1;
            }
        }
    }
    // Object descriptors remain stable under R8; callback classes may be renamed.
    private static boolean validCommit(Object value) { return value instanceof CommitInvocation; }
    private static int invokeCommit(Object value, byte[] session, byte[] message, byte[] plaintext) {
        try { return ((CommitInvocation) value).invoke(session, message, plaintext); }
        finally { java.util.Arrays.fill(plaintext, (byte) 0); }
    }
}
