// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Public framing and real JNI rejection controls; not issuer or lifecycle evidence. */
final class CredentialBridgeProbe {
    private CredentialBridgeProbe() { }
    private static byte[] id(int n) { byte[] value = new byte[32]; Arrays.fill(value, (byte)n); return value; }
    private static void require(boolean value) { if (!value) throw new AssertionError("credential metadata changed"); }
    private static void rejected(Class<? extends Throwable> type, Runnable action) {
        try { action.run(); } catch (Throwable error) {
            if (type.isInstance(error)) return;
            throw new AssertionError("wrong credential rejection", error);
        }
        throw new AssertionError("credential input admitted");
    }
    private static byte[] metadata(boolean proposal, int version, int mode) {
        int base = proposal ? 296 : 248, length = base + (version == 1 ? 0 : 33);
        ByteBuffer frame = ByteBuffer.allocate(4 + base + 33); frame.putInt(length);
        byte[] value = new byte[length]; ByteBuffer input = ByteBuffer.wrap(value);
        input.put(((proposal ? "QPCRNP0" : "QPCRNC0") + version).getBytes(StandardCharsets.US_ASCII));
        for (int offset : proposal ? new int[] {8,40,72,104,136,168,216,264} : new int[] {8,40,72,104,136,168,216}) {
            input.position(offset); input.put(id(offset));
        }
        input.putLong(200, 1).putLong(208, 2);
        if (proposal) input.putLong(248, 1).putLong(256, 3);
        if (version != 1) { input.position(base); input.put((byte)mode).put(id(9)); }
        frame.put(value); return frame.array();
    }
    private static void records() {
        for (int version = 1; version <= 3; ++version) {
            for (int mode = 0; mode <= (version == 2 ? 1 : 0); ++mode) {
                byte[] wire = metadata(true, version, mode);
                PolicyRenewalProposal proposal = PolicyRenewalProposal.fromNative(wire);
                PolicyRenewalCancellation cancellation = PolicyRenewalCancellation.fromNative(metadata(false, version, mode));
                require(proposal.adoptsPolicy() == (version == 2 && mode == 1));
                require(cancellation.adoptsPolicy() == proposal.adoptsPolicy());
                require((proposal.policyStatement() != null) == (version == 2));
                require((proposal.independentPolicyStatement() != null) == (version == 3));
                require((cancellation.independentPolicyStatement() != null) == (version == 3));
                require(proposal.statement().equals(proposal.adoptsPolicy()
                    ? new Ids.CredentialStatement(id(9)) : proposal.credentialStatement()));
                byte[] original = proposal.encoded(); wire[20] ^= 1; require(Arrays.equals(original, proposal.encoded()));
                if (version != 1) {
                    rejected(IllegalStateException.class, () -> new CredentialRenewalProposal(proposal.encoded()));
                    rejected(IllegalStateException.class, () -> new CredentialRenewalCancellation(cancellation.encoded()));
                }
            }
        }
        for (boolean proposal : new boolean[] {false,true}) {
            int base = proposal ? 296 : 248;
            byte[] wire = metadata(proposal, 3, 0);
            byte[][] invalid = {metadata(proposal,3,1), metadata(proposal,3,2), metadata(proposal,4,0),
                Arrays.copyOf(wire,wire.length-1), Arrays.copyOf(wire,wire.length+1), wire.clone(), metadata(proposal,1,0)};
            Arrays.fill(invalid[5],4+base+1,invalid[5].length,(byte)0);
            invalid[6][invalid[6].length-1] = 1;
            for (byte[] value : invalid) rejected(IllegalStateException.class, () -> {
                if (proposal) PolicyRenewalProposal.fromNative(value); else PolicyRenewalCancellation.fromNative(value);
            });
        }
        require(!new Ids.PolicyContinuationStatement(id(9)).equals(new Ids.PolicyStatement(id(9))));
    }
    private static byte[] request() {
        ByteBuffer out = ByteBuffer.allocate(CredentialRenewalRequest.NATIVE_BYTES);
        out.put(id(1)).put(id(2)).put(id(3)).put(id(4)).putLong(1).put(id(4));
        out.position(208); out.putLong(2).put(id(5)).putLong(1).put(id(6));
        out.putLong(Long.MIN_VALUE).putLong(Long.MIN_VALUE+1).put(id(7));
        for (int value = 11; value <= 14; ++value) PolicyCodec.publicRecord(out, new byte[] {(byte)value});
        return out.array();
    }
    private static void requests() {
        byte[] wire = request(); CredentialRenewalRequest value = CredentialRenewalRequest.fromNative(wire);
        require(value.previousValidUntil().toString().equals("9223372036854775809"));
        require(value.currentPolicyAuthorization() == null && value.previousRosterCheckpoint().version().equals(new Counter64("2")));
        wire[340] = 99; require(Arrays.equals(value.originalCredential(),new byte[]{11}));
        byte[] copy = value.originalOwner(); copy[0] = 99; require(value.originalOwner()[0] == 3);
        for (int offset : new int[] {168,203,204,341}) {
            byte[] bad = request(); bad[offset] = 1;
            rejected(IllegalStateException.class, () -> CredentialRenewalRequest.fromNative(bad));
        }
        byte[] bad = request(); ByteBuffer.wrap(bad).putInt(200,2);
        rejected(IllegalStateException.class, () -> CredentialRenewalRequest.fromNative(bad));
        for (int size : new int[] {0,33119,33121}) rejected(IllegalStateException.class, () -> CredentialRenewalRequest.fromNative(new byte[size]));
        byte[] adopted = request(); ByteBuffer.wrap(adopted).position(168).put(id(8)).putInt(1);
        require(CredentialRenewalRequest.fromNative(adopted).currentPolicyAuthorization().equals(new Ids.PolicyAuthorization(id(8))));
    }
    static void run() {
        records(); requests();
        for (int command = Native.CREDENTIAL_STAGE_CONTINUED; command <= Native.CREDENTIAL_WITNESSED_REQUEST; ++command) {
            final int operation = command;
            rejected(NullPointerException.class, () -> Native.credentialCommand(0, operation, null, 0));
            if (operation != Native.CREDENTIAL_STAGE_CONTINUED)
                rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, operation, new byte[0][], 1));
        }
        for (int command : new int[] {Native.CREDENTIAL_REQUEST,Native.CREDENTIAL_WITNESSED_REQUEST}) {
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0,command,new byte[][] {new byte[31]},0));
            rejected(ContinuityFailure.class, () -> Native.credentialCommand(0,command,new byte[][] {id(1)},0));
        }
        for (int command : new int[] {Native.CREDENTIAL_PREPARE_CONTINUED,Native.CREDENTIAL_CANCEL_CONTINUED,Native.CREDENTIAL_RECONCILE_LOCAL})
            rejected(ContinuityFailure.class, () -> Native.credentialCommand(0,command,new byte[0][],0));
        rejected(ContinuityFailure.class, () -> Native.credentialCommand(0,Native.CREDENTIAL_COMMIT_CONTINUED,new byte[][] {id(1),id(2)},0));
        rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0,20,new byte[0][],0));
        JointPolicyBridgeProbe.run();
    }
}
