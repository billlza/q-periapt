// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import dev.qperiapt.continuity.android.ConfigurationInputs;
import dev.qperiapt.continuity.android.ContinuityConfiguration;
import dev.qperiapt.continuity.android.ContinuityFailure;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Separate JVM process consumer of the public API and freshly signed test inputs. */
public final class ConfigurationProbe {
    private ConfigurationProbe() { }
    private static byte[] read(Path root, String name) throws Exception { return Files.readAllBytes(root.resolve(name)); }
    private static byte[] keyDigest(Path root) throws Exception {
        byte[] key = read(root, "wrap.key");
        try { return java.security.MessageDigest.getInstance("SHA-256").digest(key); }
        finally { java.util.Arrays.fill(key, (byte) 0); }
    }
    private static void require(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }
    private static ContinuityFailure fails(int code, Runnable call) {
        try { call.run(); } catch (ContinuityFailure failure) {
            require(failure.code() == code, "expected native " + code + ", received " + failure.code() + ": " + failure);
            require(!failure.operation().isEmpty() && !failure.getMessage().isEmpty(), "missing native diagnostic");
            return failure;
        }
        throw new AssertionError("expected native failure " + code);
    }
    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 4) throw new IllegalArgumentException("inputs path profile operation");
        Path inputs = Path.of(arguments[0]), path = Path.of(arguments[1]);
        boolean recoverable = arguments[2].equals("recoverable");
        if (!recoverable && !arguments[2].equals("fixed")) throw new IllegalArgumentException("profile");
        ConfigurationInputs.SdkTrust trust = recoverable
            ? ConfigurationInputs.SdkTrust.recoverable(read(inputs, "recovery-scope"), read(inputs, "sdk-root"), read(inputs, "recovery-root"))
            : ConfigurationInputs.SdkTrust.fixed(read(inputs, "sdk-root"));
        ConfigurationInputs.ProtocolPolicy protocol = new ConfigurationInputs.ProtocolPolicy(read(inputs, "family"),
            read(inputs, "policy-root"), Long.toUnsignedString(ByteBuffer.wrap(read(inputs, "policy-version")).getLong()),
            read(inputs, "policy-digest"), read(inputs, "protocol-policy"));
        ConfigurationInputs.LocalTlsIdentity tls = new ConfigurationInputs.LocalTlsIdentity(read(inputs, "tls-cert"), read(inputs, "tls-key"));
        try {
            ConfigurationInputs.Initial initial = new ConfigurationInputs.Initial(trust, read(inputs, "sdk-policy"),
                read(inputs, "sdk-signature"), recoverable ? read(inputs, "recovery-enrollment") : new byte[0], protocol, tls);
            switch (arguments[3]) {
                case "create" -> {
                    require(!Files.exists(path), "fresh path required");
                    try (ContinuityConfiguration owner = ContinuityConfiguration.prepareCreate(path.toString(), initial)) {
                        require(!Files.exists(path), "prepare performed installation I/O");
                        // The prepared native owner has its own copy, independent of caller lifetime.
                        tls.close();
                        owner.finishOpen();
                        require(Files.isDirectory(path), "missing installation");
                    }
                }
                case "reconcile" -> {
                    require(Files.isDirectory(path), "original installation required");
                    try (ContinuityConfiguration owner = ContinuityConfiguration.prepareReconcile(path.toString(), initial)) { owner.finishOpen(); }
                }
                case "open" -> {
                    require(Files.isDirectory(path), "original installation required");
                    try (ContinuityConfiguration owner = ContinuityConfiguration.prepareOpen(path.toString(), trust, protocol)) { owner.finishOpen(); }
                }
                case "duplicate" -> {
                    byte[] before = keyDigest(path);
                    try (ContinuityConfiguration owner = ContinuityConfiguration.prepareCreate(path.toString(), initial)) {
                        fails(500, owner::finishOpen);
                    }
                    require(java.util.Arrays.equals(before, keyDigest(path)), "duplicate creation changed original wrapping key");
                }
                case "absent" -> {
                    require(!Files.exists(path), "fresh path required");
                    try (ContinuityConfiguration owner = ContinuityConfiguration.prepareOpen(path.toString(), trust, protocol)) {
                        fails(203, owner::finishOpen);
                    }
                    try (ContinuityConfiguration owner = ContinuityConfiguration.prepareReconcile(path.toString(), initial)) {
                        fails(203, owner::finishOpen);
                    }
                    require(!Files.exists(path), "missing installation was recreated");
                }
                case "symlink-parent" -> {
                    Path real = Files.createTempDirectory(path.getParent(), "private-parent-");
                    Files.createSymbolicLink(path, real);
                    try (ContinuityConfiguration owner = ContinuityConfiguration.prepareCreate(path.resolve("installation").toString(), initial)) {
                        fails(500, owner::finishOpen);
                    }
                    require(!Files.exists(real.resolve("installation")), "symlink parent was followed");
                }
                case "permission-parent" -> {
                    Files.createDirectory(path);
                    Files.setPosixFilePermissions(path, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
                    try (ContinuityConfiguration owner = ContinuityConfiguration.prepareCreate(path.resolve("installation").toString(), initial)) {
                        fails(500, owner::finishOpen);
                    }
                    require(!Files.exists(path.resolve("installation")), "nonprivate parent was admitted");
                }
                case "cancel" -> {
                    require(!Files.exists(path), "fresh path required");
                    ContinuityConfiguration owner = ContinuityConfiguration.prepareCreate(path.toString(), initial);
                    try (owner) {
                        owner.cancel(); fails(302, owner::finishOpen); fails(2, owner::finishOpen);
                    }
                    fails(2, owner::finishOpen); fails(2, owner::close);
                    require(!Files.exists(path), "cancel created state");
                }
                case "capacity" -> {
                    List<ContinuityConfiguration> owners = new ArrayList<>();
                    try {
                        for (int i = 0; i < 64; ++i) owners.add(ContinuityConfiguration.prepareCreate(path.toString(), initial));
                        fails(4, () -> ContinuityConfiguration.prepareCreate(path.toString(), initial));
                        owners.remove(0).close();
                        owners.add(ContinuityConfiguration.prepareCreate(path.toString(), initial));
                    } finally { for (ContinuityConfiguration owner : owners) owner.close(); }
                    require(!Files.exists(path), "capacity test created state");
                }
                default -> throw new IllegalArgumentException("operation");
            }
        } finally { tls.close(); }
        System.out.println("configuration:" + arguments[2] + ":" + arguments[3] + ":passed");
    }
}
