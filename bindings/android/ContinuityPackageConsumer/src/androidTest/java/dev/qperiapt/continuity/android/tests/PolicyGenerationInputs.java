// SPDX-License-Identifier: Apache-2.0 OR MIT
package dev.qperiapt.continuity.android.tests;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.LinkOption;

/** Separate immutable issuer inputs while retaining the original installation. */
final class PolicyGenerationInputs {
    private PolicyGenerationInputs() { }
    static File select(File base, String generation, String operation) throws Exception {
        File original = new File(base, "inputs");
        if (generation.equals("original")) return original;
        if (!generation.equals("next") || !operation.startsWith("policy-"))
            throw new IllegalArgumentException("policy input generation");
        File target = new File(base, "cycle-inputs");
        if (Files.exists(target.toPath(), LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isDirectory(target.toPath(), LinkOption.NOFOLLOW_LINKS))
                throw new IllegalStateException("next input directory");
            return target;
        }
        if (!operation.equals("policy-joint-request") || !Files.isDirectory(original.toPath(), LinkOption.NOFOLLOW_LINKS))
            throw new IllegalStateException("original inputs must precede the next issuer request");
        copy(original, target, true);
        return target;
    }
    private static void copy(File source, File target, boolean original) throws Exception {
        if (!target.mkdir()) throw new IllegalStateException("create next issuer inputs");
        File[] entries = source.listFiles();
        if (entries == null || entries.length > 128) throw new IllegalStateException("issuer input inventory");
        for (File entry : entries) {
            String name = entry.getName();
            if (original && (name.equals("policy-target") || name.startsWith("credential-")
                    || name.startsWith("joint-") || name.startsWith("renewal-") || name.startsWith("renewed-"))) continue;
            if (Files.isDirectory(entry.toPath(), LinkOption.NOFOLLOW_LINKS)) {
                if (!original || !name.equals("peer")) throw new IllegalStateException("nested issuer inputs");
                copy(entry, new File(target, name), false);
            } else {
                if (!Files.isRegularFile(entry.toPath(), LinkOption.NOFOLLOW_LINKS) || Files.size(entry.toPath()) > 65536)
                    throw new IllegalStateException("issuer input file");
                PolicyInputs.copyOriginal(source, target, name);
            }
        }
    }
}
