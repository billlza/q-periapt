// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import android.app.Instrumentation;
import android.os.Bundle;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/** Qualification APK only: API 37 real-process consumer; not included in the library. */
public final class ConfigurationInstrumentation extends Instrumentation {
    private Bundle arguments;
    private static String apkDigest(String path) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        try (InputStream input = new java.io.FileInputStream(path)) {
            byte[] bytes = new byte[8192]; int count;
            while ((count = input.read(bytes)) != -1) digest.update(bytes, 0, count);
        }
        StringBuilder hex = new StringBuilder();
        for (byte value : digest.digest()) hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return hex.toString();
    }
    private void grantInputs(File inputs) throws Exception {
        String[] names = {"grant-certificate", "grant-roster", "trusted-account", "trusted-roster-version", "trusted-roster-digest"};
        int[] minimum = {1,1,32,8,32}, maximum = {8192,8192,32,8,32};
        byte[][] values = new byte[names.length][];
        for (int i = 0; i < names.length; ++i) {
            String encoded = arguments.getString(names[i]);
            if (encoded == null || encoded.length() > 10924) throw new IllegalArgumentException("missing or oversized signed input");
            values[i] = android.util.Base64.decode(encoded, android.util.Base64.NO_WRAP);
            if (values[i].length < minimum[i] || values[i].length > maximum[i]) throw new IllegalArgumentException("signed input width");
        }
        for (int i = 0; i < names.length; ++i) {
            java.nio.file.Path path = new File(inputs, names[i]).toPath();
            try { java.nio.file.Files.write(path, values[i], java.nio.file.StandardOpenOption.CREATE_NEW, java.nio.file.StandardOpenOption.WRITE); }
            catch (java.nio.file.FileAlreadyExistsException exists) {
                if (!java.util.Arrays.equals(values[i], java.nio.file.Files.readAllBytes(path))) throw new IllegalStateException("original signed input changed", exists);
            }
        }
    }
    @Override public void onCreate(Bundle arguments) { this.arguments = arguments; start(); }
    @Override public void onStart() {
        Bundle result = new Bundle();
        result.putInt("pid", android.os.Process.myPid());
        try {
            result.putString("apk_sha256", apkDigest(getTargetContext().getPackageCodePath()));
            String profile = arguments.getString("profile"), operation = arguments.getString("operation");
            if (!("fixed".equals(profile) || "recoverable".equals(profile))) throw new IllegalArgumentException("profile");
            if (operation == null) throw new IllegalArgumentException("operation");
            boolean managed = operation.startsWith("managed-");
            String baseOperation = managed ? operation.substring(8) : operation;
            boolean authority = operation.startsWith("authority-");
            boolean policy = operation.startsWith("policy-");
            boolean roster = operation.startsWith("roster-");
            boolean retired = operation.startsWith("retired-owned-");
            boolean root = operation.startsWith("root-");
            boolean pending = operation.startsWith("pending-");
            boolean credential = operation.startsWith("credential-");
            boolean witnessed = operation.startsWith("witness-") || managed || credential;
            boolean enrollment = operation.startsWith("enrollment-") || witnessed || authority || policy || roster || retired || root || pending;
            boolean peer = operation.startsWith("peer-");
            String slot = arguments.getString("slot", "original");
            if (!(slot.equals("original") || slot.equals("successor"))) throw new IllegalArgumentException("installation slot");
            File base = new File(getTargetContext().getFilesDir().getCanonicalFile(), "continuity-" + slot);
            try { android.system.Os.mkdir(base.getPath(), 0700); }
            catch (android.system.ErrnoException failure) {
                if (failure.errno != android.system.OsConstants.EEXIST) throw failure;
            }
            android.system.StructStat directory = android.system.Os.lstat(base.getPath());
            if (!android.system.OsConstants.S_ISDIR(directory.st_mode)
                    || (directory.st_mode & 0777) != 0700 || directory.st_uid != android.os.Process.myUid()) {
                throw new IllegalStateException("private consumer parent admission");
            }
            File inputs = PolicyGenerationInputs.select(base, arguments.getString("policy-generation", "original"), operation);
            if (!inputs.isDirectory()) {
                if (pending) throw new IllegalStateException("original pending-write enrollment inputs are absent");
                if (!inputs.mkdir()) throw new IllegalStateException("create input directory");
                if (roster || retired || root) throw new IllegalStateException("original enrollment inputs are absent");
                if (policy || operation.equals("managed-witness-create")) {
                    PolicyInputs.initial(inputs, arguments, profile);
                } else {
                java.util.List<String> names = new java.util.ArrayList<>(java.util.Arrays.asList("sdk-policy", "sdk-signature", "sdk-root", "family", "policy-root",
                        "policy-version", "policy-digest", "protocol-policy", "tls-cert", "tls-key",
                        "recovery-scope", "recovery-root", "recovery-enrollment"));
                if (enrollment || peer) { names.add("enrollment-root"); names.add("enrollment-intent"); }
                for (String name : names) {
                    try (InputStream source = getContext().getAssets().open("inputs/" + name);
                            FileOutputStream target = new FileOutputStream(new File(inputs, name))) {
                        byte[] buffer = new byte[4096];
                        try {
                            int length;
                            while ((length = source.read(buffer)) != -1) target.write(buffer, 0, length);
                            target.getFD().sync();
                        } finally { java.util.Arrays.fill(buffer, (byte) 0); }
                    }
                }
                }
            }
            boolean isolated = "capacity".equals(operation) || "cancel".equals(operation) || "absent".equals(operation)
                || "symlink-parent".equals(operation) || "permission-parent".equals(operation);
            String leaf = profile + (isolated ? "-" + operation : "-installation");
            if (enrollment || peer) {
                String label = arguments.getString("label");
                if (label == null || !label.matches("[a-z][a-z0-9.-]{0,63}")) throw new IllegalArgumentException("result label");
                if ("enrollment-reject".equals(operation) || "enrollment-activate".equals(operation)
                        || "witness-prepare".equals(baseOperation) || "authority-create".equals(operation) || "policy-prepare".equals(operation)) grantInputs(inputs);
                File publicResult = new File(base, label);
                String[] call = {inputs.getPath(), new File(base, leaf).getPath(), profile, operation, publicResult.getPath()};
                if (pending) {
                    PendingWriteInputs.install(inputs, arguments, operation);
                    PendingWriteProbe.main(call);
                } else if (root) {
                    RootInputs.install(inputs,arguments,operation,profile);
                    RootOwnedProbe.run(call,value -> {
                        Bundle cut=new Bundle();cut.putString("stage","root-cut");
                        cut.putInt("pid",android.os.Process.myPid());cut.putString("apk_sha256",result.getString("apk_sha256"));
                        cut.putString("operation",operation);cut.putString("label",label);
                        cut.putString("report",android.util.Base64.encodeToString(value,android.util.Base64.NO_WRAP));
                        sendStatus(3,cut);
                    });
                } else if (retired) {
                    RetirementInputs.install(inputs, arguments, operation);
                    RetiredOwnedProbe.run(call, originalReport -> {
                        Bundle cut = new Bundle(); cut.putString("stage", "retirement-cut");
                        cut.putInt("pid", android.os.Process.myPid());
                        cut.putString("apk_sha256", result.getString("apk_sha256"));
                        cut.putString("operation", operation); cut.putString("label", label);
                        cut.putString("report", android.util.Base64.encodeToString(originalReport, android.util.Base64.NO_WRAP));
                        sendStatus(3, cut);
                    });
                } else if (policy) {
                    PolicyInputs.install(inputs, arguments, operation, profile);
                    PolicyProbe.main(call);
                } else if (roster) {
                    RosterInputs.install(inputs,arguments,operation);
                    if(operation.startsWith("roster-witness-"))RosterWitnessProbe.main(call);
                    else RosterProbe.main(call);
                } else if (peer) {
                    PeerInputs.install(inputs, arguments, operation);
                    PeerProbe.run(call, port -> {
                        Bundle ready = new Bundle(); ready.putInt("port", port); ready.putInt("pid", android.os.Process.myPid());
                        ready.putString("apk_sha256", result.getString("apk_sha256")); ready.putString("stage", "peer-listening");
                        sendStatus(2, ready);
                    });
                } else if (operation.startsWith("credential-local-")) {
                    WitnessInputs.installLocalCredential(inputs,arguments,operation);
                    if(operation.equals("credential-local-identity") || operation.equals("credential-local-active") || operation.equals("credential-local-send")) PeerInputs.install(inputs,arguments,"peer-retry");
                    CredentialLocalProbe.main(call);
                } else if (witnessed || authority) {
                    WitnessInputs.install(inputs, arguments);
                    if (authority || credential || (managed && !baseOperation.equals("witness-create")
                            && !baseOperation.equals("witness-wrong") && !baseOperation.equals("witness-resume")))
                        WitnessInputs.installAuthority(inputs, arguments, operation);
                    if (credential) {
                        WitnessInputs.installCredential(inputs, arguments, operation);
                        if (operation.startsWith("credential-peer-")) PeerInputs.install(inputs, arguments, operation.substring("credential-".length()));
                        if (operation.startsWith("credential-remote-")) {
                            WitnessInputs.installRemoteCredential(inputs,arguments,operation);
                            if (operation.equals("credential-remote-uncertain") || operation.equals("credential-remote-retry")) PeerInputs.install(inputs,arguments,"peer-retry");
                        }
                        if(operation.startsWith("credential-terminal-")) {
                            WitnessInputs.installTerminalCredential(inputs,arguments,operation);
                            if(operation.equals("credential-terminal-send")) PeerInputs.install(inputs,arguments,"peer-retry");
                        }
                        CredentialProbe.main(call);
                    } else if (authority) {
                        if (operation.equals("authority-peer-associate")) PeerInputs.installApproval(inputs, arguments);
                        AuthorityProbe.main(call);
                    } else WitnessProbe.main(call);
                } else EnrollmentProbe.main(call);
                byte[] bytes = java.nio.file.Files.readAllBytes(publicResult.toPath());
                int requestWidth = operation.equals("policy-request") ? 33176
                    : operation.equals("policy-credential-request") || operation.equals("policy-credential-next-request")
                        || operation.equals("policy-joint-request") || operation.equals("policy-joint-next-request") ? 33120 : 0;
                if (requestWidth != 0 ? bytes.length != requestWidth : bytes.length < 1 || bytes.length > (retired || root || pending ? 65536 : 8192))
                    throw new IllegalStateException("public result width");
                result.putString("result_payload", android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP));
                result.putString("result", profile + ":" + operation + ":passed");
            } else {
                ConfigurationProbe.main(new String[] {inputs.getPath(), new File(base, leaf).getPath(), profile, operation});
                result.putString("result", "configuration:" + profile + ":" + operation + ":passed");
            }
            finish(-1, result);
        } catch (Exception | AssertionError failure) {
            result.putString("failure", failure.toString());
            try {
                File path = getTargetContext().getFilesDir().getCanonicalFile();
                StringBuilder admission = new StringBuilder();
                while (path != null) {
                    admission.append(path.getPath()).append(":mode=")
                        .append(Integer.toOctalString(android.system.Os.stat(path.getPath()).st_mode & 0777));
                    try {
                        java.io.FileDescriptor fd = android.system.Os.open(path.getPath(),
                            android.system.OsConstants.O_RDONLY | android.system.OsConstants.O_NOFOLLOW
                                | android.system.OsConstants.O_CLOEXEC, 0);
                        android.system.Os.close(fd);
                        admission.append(":directory-open=ok;");
                    } catch (android.system.ErrnoException denied) { admission.append(":directory-open-errno=").append(denied.errno).append(';'); }
                    path = path.getParentFile();
                }
                result.putString("directory_admission", admission.toString());
            } catch (Exception diagnostic) { result.putString("diagnostic_failure", diagnostic.toString()); }
            finish(1, result);
        }
    }
}
