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
    static native byte[] peerCommand(long handle, int operation, byte[][] inputs, long target);
    static native byte[] peerServer(long handle, int operation, byte[][] inputs, Object callback);
    static native void provisionAuthority(byte[][] inputs);
    static native long prepareAuthority(byte[][] inputs, boolean create);
    static native byte[] authorityCommand(long handle, int operation, byte[][] inputs, long version);
    static native void selectAuthority(long enrollment, long registry, byte[][] checkpoint);
    static native byte[] credentialCommand(long handle, int operation, byte[][] inputs, long version);
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
