// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android;

/** JNI field boundaries and facade validation; real joint lifecycle runs separately. */
final class JointPolicyBridgeProbe {
    private JointPolicyBridgeProbe() { }
    private static byte[] id() { byte[] value = new byte[32]; value[0] = 1; return value; }
    private static void rejected(Class<? extends Throwable> type, Runnable action) {
        try { action.run(); } catch (Throwable error) {
            if (type.isInstance(error)) return;
            throw new AssertionError("wrong joint policy rejection", error);
        }
        throw new AssertionError("joint policy input admitted");
    }
    private static void nativeCode(int expected, Runnable action) {
        try { action.run(); } catch (ContinuityFailure failure) {
            if (failure.code() == expected) return;
            throw new AssertionError("wrong joint policy native code", failure);
        }
        throw new AssertionError("invalid native owner admitted");
    }
    static void run() {
        AccountPin pin = new AccountPin(id(), new byte[1985], id(), new Counter64("1"), id());
        ConfigurationInputs.ProtocolPolicy policy = new ConfigurationInputs.ProtocolPolicy(id(), new byte[1985], "1", id(), new byte[] {1});
        Ids.CredentialRenewal operation = new Ids.CredentialRenewal(id());
        byte[][] fields = PolicyCodec.join(new byte[][] {new byte[] {1}}, PolicyCodec.pin(pin),
            new byte[][] {id(), new byte[] {1}}, PolicyCodec.document(policy), new byte[][] {new byte[0]});
        int[] minimum = {1,32,1985,32,8,32,32,1,32,1985,8,32,1,0};
        int[] maximum = {65536,32,1985,32,8,32,32,7746,32,1985,8,32,8192,32};
        for (int command : new int[] {Native.CREDENTIAL_STAGE_JOINT, Native.CREDENTIAL_ACTIVATE_JOINT}) {
            rejected(NullPointerException.class, () -> Native.credentialCommand(0, command, null, 0));
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, command, new byte[0][], 1));
        }
        for (int field = 0; field < fields.length; ++field) {
            byte[][] missing = fields.clone(); missing[field] = null;
            rejected(NullPointerException.class, () -> Native.credentialCommand(0, Native.CREDENTIAL_STAGE_JOINT, missing, 0));
            for (int length : new int[] {minimum[field] - 1, maximum[field] + 1}) {
                if (length < 0) continue;
                byte[][] invalid = fields.clone(); invalid[field] = new byte[length];
                rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, Native.CREDENTIAL_STAGE_JOINT, invalid, 0));
            }
        }
        for (int length = 1; length < 32; ++length) {
            byte[][] invalid = fields.clone(); invalid[13] = new byte[length];
            rejected(IllegalArgumentException.class, () -> Native.credentialCommand(0, Native.CREDENTIAL_STAGE_JOINT, invalid, 0));
        }
        for (int length : new int[] {0,32}) {
            byte[][] acceptedShape = fields.clone(); acceptedShape[13] = new byte[length];
            nativeCode(101, () -> Native.credentialCommand(0, Native.CREDENTIAL_STAGE_JOINT, acceptedShape, 0));
        }
        nativeCode(2, () -> Native.credentialCommand(0, Native.CREDENTIAL_ACTIVATE_JOINT, new byte[0][], 0));
        // A fabricated invalid owner is never closed or activated: only public preflight is exercised.
        ContinuityEnrollment owner = new ContinuityEnrollment(Long.MAX_VALUE);
        for (int length : new int[] {0,65537})
            rejected(IllegalArgumentException.class, () -> owner.stagePolicyContinuation(new byte[length], pin, operation, new byte[] {1}, policy, null));
        for (int length : new int[] {0,7747})
            rejected(IllegalArgumentException.class, () -> owner.stagePolicyContinuation(new byte[] {1}, pin, operation, new byte[length], policy, null));
        rejected(NullPointerException.class, () -> owner.stagePolicyContinuation(new byte[] {1}, pin, null, new byte[] {1}, policy, null));
        rejected(NullPointerException.class, () -> owner.stagePolicyContinuation(new byte[] {1}, pin, operation, new byte[] {1}, null, null));
    }
}
